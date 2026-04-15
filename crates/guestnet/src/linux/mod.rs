//! Builds and tears down a session's network over netlink. Forking ~16 ip(8) and conntrack(8) helpers used to be most
//! of a boot's network setup time.

use std::fs::File;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::AsRawFd as _;

use anyhow::Context as _;
use futures_util::TryStreamExt as _;
use nix::unistd::Uid;
use rtnetlink::packet_route::link::{InfoData, InfoVeth, LinkAttribute};
use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute};
use rtnetlink::{Handle, LinkMessageBuilder, LinkUnspec, LinkVeth, RouteMessageBuilder};

use crate::{GUEST_GATEWAY, GUEST_TAP, NETNS_VETH, Slot, TAP_PREFIX, netns_ruleset};

mod conntrack;
mod netns;
mod tap;

pub use netns::{delete_netns, list_netns};

/// A restored guest's ARP cache has the snapshotted gateway's MAC, so every namespace's tap has to share it.
const GATEWAY_MAC: [u8; 6] = [0x06, 0x00, 0xac, 0x10, 0x00, 0x01];

/// Session networks, through an rtnetlink connection to the host namespace.
pub struct Net {
    host: Handle,
}

/// Where guest traffic leaves the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uplink {
    pub iface: String,
    /// The uplink's preferred source address, if the route names one.
    pub source: Option<Ipv4Addr>,
}

impl Net {
    /// Connects to rtnetlink in the calling thread's namespace. Needs a tokio runtime to drive the connection.
    pub fn new() -> anyhow::Result<Self> {
        let (conn, host, _) = rtnetlink::new_connection().context("rtnetlink connection")?;
        tokio::spawn(conn);
        Ok(Self { host })
    }

    /// Builds the slot's namespace: a veth from the host into it, and inside it the guest's tap, owned by `owner`
    /// (`None` leaves it to root), routed and translated out the veth.
    pub async fn create_session(&self, slot: &Slot, owner: Option<Uid>) -> anyhow::Result<()> {
        let (tap, path) = (slot.tap(), slot.netns_path());
        conntrack::delete(slot.guest).await?;
        netns::add(&path).await?;

        let ns = File::open(&path).with_context(|| format!("open {}", path.display()))?;
        let peer = LinkMessageBuilder::<LinkUnspec>::new().name(NETNS_VETH.to_owned()).setns_by_fd(ns.as_raw_fd()).build();
        let veth = LinkVeth::new(&tap, NETNS_VETH).set_info_data(InfoData::Veth(InfoVeth::Peer(peer))).build();
        self.host.link().add(veth).execute().await.with_context(|| format!("add veth {tap}"))?;
        drop(ns);

        // do this before link up, so neither end ever picks up a link-local v6 address.
        disable_ipv6(&tap)?;
        let index = require_link(&self.host, &tap).await?;
        link_up(&self.host, index, slot.gateway).await?;

        let slot = *slot;
        netns::run_in(&path, move || configure_netns(slot, owner)).await
    }

    /// Removes the slot's network, skipping parts that are already gone. Every part gets tried so one stuck link can't
    /// leak the namespace pin or conntrack flows. Returns the first error and logs the rest.
    pub async fn delete_session(&self, slot: &Slot) -> anyhow::Result<()> {
        // link first: the namespace's async teardown mustn't hold up reuse of the veth's name. Also, once unpinned it
        // can take the veth with it between delete_tap's lookup and its delete.
        let tap = self.delete_tap(&slot.tap()).await;
        let netns = slot.netns();
        let netns = tokio::task::spawn_blocking(move || delete_netns(&netns)).await.unwrap_or_else(|err| Err(err.into()));
        let results = [tap, netns, conntrack::delete(slot.guest).await];
        let mut errors = results.into_iter().filter_map(Result::err);
        let Some(first) = errors.next() else { return Ok(()) };
        for err in errors {
            tracing::error!(tap = %slot.tap(), error = format!("{err:#}"), "delete session network");
        }
        Err(first)
    }

    /// Deletes a host link, if it exists.
    pub async fn delete_tap(&self, name: &str) -> anyhow::Result<()> {
        let Some(index) = link_index(&self.host, name).await.with_context(|| format!("find {name}"))? else { return Ok(()) };
        self.host.link().del(index).execute().await.with_context(|| format!("delete {name}"))
    }

    /// Every host link named like a session's tap, so recovery can sweep up orphans.
    pub async fn list_taps(&self) -> anyhow::Result<Vec<String>> {
        let links: Vec<_> = self.host.link().get().execute().try_collect().await.context("list links")?;
        Ok(links
            .into_iter()
            .filter_map(|l| l.attributes.into_iter().find_map(|a| if let LinkAttribute::IfName(n) = a { Some(n) } else { None }))
            .filter(|name| name.starts_with(TAP_PREFIX))
            .collect())
    }

    /// The interface and source address the host routes 1.1.1.1 through.
    pub async fn uplink(&self) -> anyhow::Result<Uplink> {
        let probe = RouteMessageBuilder::<Ipv4Addr>::new().destination_prefix(Ipv4Addr::new(1, 1, 1, 1), 32).build();
        let route = self.host.route().get(probe).execute().try_next().await.context("route get")?.context("no route to 1.1.1.1")?;
        let (mut oif, mut source) = (None, None);
        for attr in route.attributes {
            match attr {
                RouteAttribute::Oif(index) => oif = Some(index),
                RouteAttribute::PrefSource(RouteAddress::Inet(ip)) => source = Some(ip),
                _ => {}
            }
        }
        let oif = oif.context("route to 1.1.1.1 names no interface")?;
        let link = self.host.link().get().match_index(oif).execute().try_next().await?.context("route's link vanished")?;
        let iface = link
            .attributes
            .into_iter()
            .find_map(|a| if let LinkAttribute::IfName(n) = a { Some(n) } else { None })
            .context("route's link has no name")?;
        Ok(Uplink { iface, source })
    }
}

/// Re-pins a live session's namespace from its vmm, after a restart lost roost's mount namespace and the pin.
pub fn attach_netns(slot: &Slot, pid: u32) -> anyhow::Result<()> {
    let path = slot.netns_path();
    if path.exists() {
        return Ok(());
    }
    netns::mount_at(format!("/proc/{pid}/ns/net").as_ref(), &path)
}

/// Pipes `ruleset` to `nft -f -` in the calling thread's namespace.
pub async fn apply_ruleset(ruleset: &str) -> anyhow::Result<()> {
    use std::process::Stdio;

    use tokio::io::AsyncWriteExt as _;

    let mut child = tokio::process::Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("spawn nft")?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin.write_all(ruleset.as_bytes()).await.context("write nft ruleset")?;
    drop(stdin);
    let out = child.wait_with_output().await.context("wait for nft")?;
    anyhow::ensure!(
        out.status.success(),
        "nft -f: {}: {}{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

pub fn enable_ip_forward() -> anyhow::Result<()> {
    const PATH: &str = "/proc/sys/net/ipv4/ip_forward";
    sysctl(PATH).with_context(|| format!("sysctl {PATH}"))
}

/// Runs on a thread inside the session's namespace.
async fn configure_netns(slot: Slot, owner: Option<Uid>) -> anyhow::Result<()> {
    // "all" covers the veth end that's already here, "default" covers the tap we create next.
    for dev in ["all", "default"] {
        disable_ipv6(dev)?;
    }
    enable_ip_forward()?;
    tap::create(GUEST_TAP, owner)?;

    let (conn, ns, _) = rtnetlink::new_connection().context("rtnetlink connection in netns")?;
    tokio::spawn(conn);
    let tap = require_link(&ns, GUEST_TAP).await?;
    let mac = LinkUnspec::new_with_index(tap).address(GATEWAY_MAC.to_vec()).build();
    ns.link().set(mac).execute().await.context("set tap mac")?;
    link_up(&ns, tap, GUEST_GATEWAY).await?;

    let veth = require_link(&ns, NETNS_VETH).await?;
    link_up(&ns, veth, slot.guest).await?;
    let default = RouteMessageBuilder::<Ipv4Addr>::new().output_interface(veth).gateway(slot.gateway).build();
    ns.route().add(default).execute().await.context("add default route")?;

    apply_ruleset(&netns_ruleset(&slot)).await
}

fn sysctl(path: &str) -> io::Result<()> {
    std::fs::write(path, "1")
}

/// No sysctl directory means the kernel has no IPv6.
fn disable_ipv6(dev: &str) -> anyhow::Result<()> {
    let path = format!("/proc/sys/net/ipv6/conf/{dev}/disable_ipv6");
    match sysctl(&path) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r.with_context(|| format!("sysctl {path}")),
    }
}

/// The link's index, or `None` if there's no such link.
async fn link_index(handle: &Handle, name: &str) -> Result<Option<u32>, rtnetlink::Error> {
    match handle.link().get().match_name(name.to_owned()).execute().try_next().await {
        Ok(link) => Ok(link.map(|l| l.header.index)),
        Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -libc::ENODEV => Ok(None),
        Err(err) => Err(err),
    }
}

async fn require_link(handle: &Handle, name: &str) -> anyhow::Result<u32> {
    link_index(handle, name).await.with_context(|| format!("find {name}"))?.with_context(|| format!("find {name}: no such link"))
}

/// Addresses the link with `ip`/30 and brings it up.
async fn link_up(handle: &Handle, index: u32, ip: Ipv4Addr) -> anyhow::Result<()> {
    handle.address().add(index, IpAddr::V4(ip), 30).execute().await.with_context(|| format!("add {ip} to link {index}"))?;
    handle.link().set(LinkUnspec::new_with_index(index).up().build()).execute().await.with_context(|| format!("set link {index} up"))
}
