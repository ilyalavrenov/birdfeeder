//! Tests against the real kernel. They need root, so they're ignored by default and run by `dev/run-linux.sh
//! integration`. Each one runs in a throwaway "host" namespace so the machine's own tables, links and conntrack don't
//! get touched.
#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::fs::File;
use std::future::Future;
use std::io::{ErrorKind, Write as _};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use guestnet::{Claim, Egress, Endpoint, Host, Net, Session, Slot, host_ruleset, netns_ruleset};
use ipnet::Ipv4Net;
use nix::sched::{CloneFlags, setns};

const SUBNET: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(172, 29, 0, 0), 24);

fn run(cmd: &str) -> Result<String, String> {
    let mut args = cmd.split_whitespace();
    let out = Command::new(args.next().unwrap()).args(args).output().map_err(|e| format!("{cmd}: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if out.status.success() { Ok(stdout) } else { Err(format!("{cmd}: {}: {stdout}{}", out.status, String::from_utf8_lossy(&out.stderr))) }
}

fn must(cmd: &str) -> String {
    run(cmd).unwrap_or_else(|e| panic!("{e}"))
}

/// Runs `f` on a thread joined to the named namespace. Sockets it opens and commands it runs land there.
fn in_netns<T: Send>(name: &str, f: impl FnOnce() -> T + Send) -> T {
    let ns = File::open(format!("/var/run/netns/{name}")).unwrap();
    std::thread::scope(|s| {
        s.spawn(move || {
            setns(&ns, CloneFlags::CLONE_NEWNET).unwrap();
            f()
        })
        .join()
        .unwrap()
    })
}

/// Runs `test` in a fresh namespace standing in for the host, then removes it and the `extra` namespaces.
fn with_host<Fut: Future<Output = ()>>(name: &str, extra: &[&str], test: impl FnOnce() -> Fut + Send) {
    assert!(nix::unistd::geteuid().is_root(), "run as root");
    let host = format!("{name}-{}", std::process::id());
    must(&format!("ip netns add {host}"));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        in_netns(&host, || tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(test()));
    }));
    for ns in extra.iter().copied().chain([host.as_str()]) {
        let _ = run(&format!("ip netns del {ns}"));
    }
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

#[test]
#[ignore = "needs root"]
fn rulesets_pass_nft_check() {
    let slot = Slot::new(SUBNET, 0).unwrap();
    let endpoints = BTreeMap::from([
        ("http".to_owned(), Endpoint { host_port: 31000, guest_port: 8080 }),
        ("admin".to_owned(), Endpoint { host_port: 31001, guest_port: 9090 }),
    ]);
    let egress = Egress {
        cidr_allowlist: vec!["1.1.1.0/24".parse().unwrap()],
        fqdn_allowlist: vec!["example.com".parse().unwrap()],
        smtp_allowed: false,
    };
    let now = SystemTime::now();
    let fqdn_addrs = BTreeMap::from([(Ipv4Addr::new(93, 184, 215, 14), now + Duration::from_secs(30))]);
    let claim = Claim { endpoints: &endpoints, egress: Some(&egress), fqdn_addrs: &fqdn_addrs };
    let session = Session { name: "test-0", slot, conn_limit: std::num::NonZeroU32::new(4096), claim: Some(claim) };
    let host = Host { iface: "eth0", subnet: SUBNET, dns_port: 15353, slots: 2 };

    for ruleset in [host_ruleset(&host, &[session], now), netns_ruleset(&slot)] {
        let mut nft = Command::new("nft").args(["--check", "--file", "-"]).stdin(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        nft.stdin.take().unwrap().write_all(ruleset.as_bytes()).unwrap();
        let out = nft.wait_with_output().unwrap();
        assert!(out.status.success(), "{}\n{ruleset}", String::from_utf8_lossy(&out.stderr));
    }
}

#[test]
#[ignore = "needs root"]
fn sessions_get_a_namespace_of_their_own() {
    let slot = Slot::new(SUBNET, 62).unwrap();
    let (ns, tap, gw, guest) = (slot.netns(), slot.tap(), slot.gateway, slot.guest);
    with_host("bf-net-host", &[&ns.clone()], || async move {
        let net = Net::new().unwrap();
        net.create_session(&slot, Some(nix::unistd::Uid::from_raw(10_000))).await.unwrap();

        let in_ns = |cmd: &str| must(&format!("ip netns exec {ns} {cmd}"));
        assert!(must(&format!("ip -o -4 addr show {tap}")).contains(&format!("inet {gw}/30")));
        assert_eq!(must(&format!("cat /proc/sys/net/ipv6/conf/{tap}/disable_ipv6")).trim(), "1");
        assert!(in_ns("ip -o link show tap0").contains("link/ether 06:00:ac:10:00:01"));
        // IFF_TAP | IFF_NO_PI | IFF_PERSIST
        assert_eq!(in_ns("cat /sys/class/net/tap0/tun_flags").trim(), "0x1802");
        assert_eq!(in_ns("cat /sys/class/net/tap0/owner").trim(), "10000");
        assert_eq!(in_ns("cat /sys/class/net/tap0/group").trim(), "10000");
        assert_eq!(in_ns("cat /proc/sys/net/ipv6/conf/tap0/disable_ipv6").trim(), "1");
        assert_eq!(in_ns("cat /proc/sys/net/ipv4/ip_forward").trim(), "1");
        assert!(in_ns("ip -o -4 addr show tap0").contains("inet 172.16.0.1/30"));
        assert!(in_ns("ip -o -4 addr show wv").contains(&format!("inet {guest}/30")));
        assert!(in_ns("ip route show default").contains(&format!("default via {gw} dev wv")));
        assert!(in_ns("nft list table inet birdfeeder").contains(&format!("snat ip to {guest}")));
        in_ns(&format!("ping -c1 -W2 {gw}"));

        assert!(net.list_taps().await.unwrap().contains(&tap));
        assert!(guestnet::list_netns().unwrap().contains(&ns));

        // a live vmm keeps the namespace alive when roost loses its pin, and attaching re-pins it from the vmm.
        let mut vmm = Command::new("ip").args(["netns", "exec", &ns, "sleep", "60"]).spawn().unwrap();
        std::thread::sleep(Duration::from_millis(200));
        guestnet::delete_netns(&ns).unwrap();
        assert!(!guestnet::list_netns().unwrap().contains(&ns));
        guestnet::attach_netns(&slot, vmm.id()).unwrap();
        assert!(must(&format!("ip -n {ns} -o link show tap0")).contains("tap0"));
        vmm.kill().unwrap();
        vmm.wait().unwrap();

        net.delete_session(&slot).await.unwrap();
        assert!(run(&format!("ip link show {tap}")).is_err(), "{tap} survived");
        assert!(!guestnet::list_netns().unwrap().contains(&ns));
        net.delete_session(&slot).await.expect("deleting a deleted session is a no-op");
    });
}

/// Slot addresses get reused, so a retired guest's conntrack flows mustn't let the next guest's traffic through as
/// established.
#[test]
#[ignore = "needs root"]
fn replacement_guests_inherit_no_conntrack() {
    let slot = Slot::new(SUBNET, 63).unwrap();
    let peer_ns = format!("bf-ct-peer-{}", std::process::id());
    let peer = SocketAddr::from((Ipv4Addr::new(198, 18, 0, 2), 7));
    let guest_ns = slot.netns();
    with_host("bf-ct-host", &[&peer_ns.clone(), &guest_ns.clone()], || async move {
        guestnet::enable_ip_forward().unwrap();
        must(&format!("ip netns add {peer_ns}"));
        for cmd in [
            format!("ip link add out type veth peer name eth0 netns {peer_ns}"),
            "ip addr add 198.18.0.1/30 dev out".to_owned(),
            "ip link set out up".to_owned(),
            format!("ip -n {peer_ns} addr add 198.18.0.2/30 dev eth0"),
            format!("ip -n {peer_ns} link set eth0 up"),
            format!("ip -n {peer_ns} route add default via 198.18.0.1"),
        ] {
            must(&cmd);
        }
        let echo = in_netns(&peer_ns, || UdpSocket::bind(peer).unwrap());
        std::thread::spawn(move || {
            let mut buf = [0; 16];
            while let Ok((n, from)) = echo.recv_from(&mut buf) {
                let _ = echo.send_to(&buf[..n], from);
            }
        });

        let net = Net::new().unwrap();
        let host = Host { iface: "out", subnet: SUBNET, dns_port: 15353, slots: 64 };
        let (endpoints, fqdn_addrs) = (BTreeMap::new(), BTreeMap::new());
        let apply = async |egress: Option<&Egress>| {
            let claim = Claim { endpoints: &endpoints, egress, fqdn_addrs: &fqdn_addrs };
            let session = Session { name: "conntrack-0", slot, conn_limit: std::num::NonZeroU32::new(4096), claim: Some(claim) };
            guestnet::apply_ruleset(&host_ruleset(&host, &[session], SystemTime::now())).await.unwrap();
        };
        // the probe leaves the namespace from the slot's address, same as guest traffic after the NAT.
        let probe = || {
            in_netns(&guest_ns, || {
                let sock = UdpSocket::bind((slot.guest, 40123)).unwrap();
                sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                sock.connect(peer).unwrap();
                sock.send(b"ping").unwrap();
                sock.recv(&mut [0; 16])
            })
        };

        let allowed = Egress { cidr_allowlist: vec!["198.18.0.2/32".parse().unwrap()], ..Egress::default() };
        net.create_session(&slot, None).await.unwrap();
        apply(Some(&allowed)).await;
        probe().expect("the allowed guest reaches its peer");

        net.delete_session(&slot).await.unwrap();
        apply(None).await;
        net.create_session(&slot, None).await.unwrap();
        let err = probe().expect_err("the replacement guest inherited the retired guest's flow");
        assert!(matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut), "{err}");
        net.delete_session(&slot).await.unwrap();
    });
}
