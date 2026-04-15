//! Guest networking for roost: each session's network namespace, the nftables rulesets that box it in, and the DNS gate
//! that turns a session's FQDN allowlist into addresses.
//!
//! Every guest sees the same NIC ([`GUEST_IP`] behind [`GUEST_GATEWAY`] on [`GUEST_TAP`]), so a snapshot can restore
//! into any slot. Its namespace NATs that address to [`Slot::guest`].

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::time::SystemTime;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::dnsgate::FqdnPattern;

pub mod dnsgate;
#[cfg(target_os = "linux")]
mod linux;
mod nft;

#[cfg(target_os = "linux")]
pub use linux::{Net, Uplink, apply_ruleset, attach_netns, delete_netns, enable_ip_forward, list_netns};
pub use nft::{Host, host_ruleset, netns_ruleset};

pub const GUEST_TAP: &str = "tap0";
pub const GUEST_IP: Ipv4Addr = Ipv4Addr::new(172, 16, 0, 2);
pub const GUEST_GATEWAY: Ipv4Addr = Ipv4Addr::new(172, 16, 0, 1);
pub const GUEST_MAC: &str = "06:00:ac:10:00:02";
/// The guest network every namespace reuses. The roost subnet can't overlap it.
pub const GUEST_NET: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(172, 16, 0, 0), 30);

/// The namespace end of a session's veth.
const NETNS_VETH: &str = "wv";
const TAP_PREFIX: &str = "bf";
const NETNS_PREFIX: &str = "birdfeeder-";
const NETNS_DIR: &str = "/var/run/netns";

/// One /30 of the roost subnet: network, gateway, guest, broadcast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    pub index: u32,
    /// The host end of the veth.
    pub gateway: Ipv4Addr,
    /// The guest's address after the namespace translates it.
    pub guest: Ipv4Addr,
}

impl Slot {
    /// The slot's addresses, or `None` past the subnet's last /30.
    #[must_use]
    pub fn new(subnet: Ipv4Net, index: u32) -> Option<Self> {
        if index >= slot_count(subnet) {
            return None;
        }
        let block = subnet.network().to_bits() + index * 4;
        Some(Self { index, gateway: Ipv4Addr::from_bits(block + 1), guest: Ipv4Addr::from_bits(block + 2) })
    }

    /// The host end of the session's veth.
    #[must_use]
    pub fn tap(&self) -> String {
        tap_name(self.index)
    }

    #[must_use]
    pub fn netns(&self) -> String {
        format!("{NETNS_PREFIX}{}", self.index)
    }

    #[must_use]
    pub fn netns_path(&self) -> PathBuf {
        netns_path(&self.netns())
    }
}

/// How many /30 slots `subnet` holds.
#[must_use]
pub fn slot_count(subnet: Ipv4Net) -> u32 {
    // a /0 is 2^30 slots, which still fits.
    ((1_u64 << (32 - subnet.prefix_len())) / 4) as u32
}

fn tap_name(index: u32) -> String {
    format!("{TAP_PREFIX}{index}")
}

fn netns_path(name: &str) -> PathBuf {
    PathBuf::from(NETNS_DIR).join(name)
}

/// A published guest port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub host_port: u16,
    pub guest_port: u16,
}

/// What a claimed guest can reach past the default-deny.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Egress {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cidr_allowlist: Vec<Ipv4Net>,
    /// Resolved through the DNS gate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fqdn_allowlist: Vec<FqdnPattern>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub smtp_allowed: bool,
}

/// A session as the host ruleset sees it.
#[derive(Debug, Clone, Copy)]
pub struct Session<'a> {
    /// Names the session's chain and FQDN set.
    pub name: &'a str,
    pub slot: Slot,
    /// Caps concurrent and new connections. `None` means unlimited.
    pub conn_limit: Option<NonZeroU32>,
    /// Only a claimed session publishes endpoints or gets egress past the default-deny.
    pub claim: Option<Claim<'a>>,
}

#[derive(Debug, Clone, Copy)]
pub struct Claim<'a> {
    /// Rendered in key order so the ruleset stays stable.
    pub endpoints: &'a BTreeMap<String, Endpoint>,
    pub egress: Option<&'a Egress>,
    /// Addresses the DNS gate resolved for the FQDN allowlist. Expiries are absolute so a rebuild keeps their TTLs.
    pub fqdn_addrs: &'a BTreeMap<Ipv4Addr, SystemTime>,
}

impl Session<'_> {
    fn egress(&self) -> Option<&Egress> {
        self.claim.and_then(|c| c.egress)
    }

    /// Whether the DNS gate answers this session. Also gates its FQDN set.
    pub(crate) fn fqdn_active(&self) -> bool {
        self.egress().is_some_and(|e| !e.fqdn_allowlist.is_empty())
    }

    fn chain(&self) -> String {
        format!("sess_{}", self.name.replace(['-', '.'], "_"))
    }

    fn fqdn_set(&self) -> String {
        format!("{}_fqdn", self.chain())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_carve_the_subnet_into_30s() {
        let subnet: Ipv4Net = "172.20.0.0/24".parse().unwrap();
        assert_eq!(slot_count(subnet), 64);
        assert_eq!(
            Slot::new(subnet, 1),
            Some(Slot { index: 1, gateway: Ipv4Addr::new(172, 20, 0, 5), guest: Ipv4Addr::new(172, 20, 0, 6) })
        );
        assert_eq!(Slot::new(subnet, 63).map(|s| s.guest), Some(Ipv4Addr::new(172, 20, 0, 254)));
        assert_eq!(Slot::new(subnet, 64), None);
        // an unmasked subnet still starts at its network address
        assert_eq!(Slot::new("172.20.0.9/24".parse().unwrap(), 0).map(|s| s.gateway), Some(Ipv4Addr::new(172, 20, 0, 1)));
        assert_eq!(slot_count("10.0.0.0/30".parse().unwrap()), 1);
        assert_eq!(slot_count("10.0.0.0/31".parse().unwrap()), 0);
        assert_eq!(slot_count("0.0.0.0/0".parse().unwrap()), 1 << 30);

        let slot = Slot::new(subnet, 3).unwrap();
        assert_eq!((slot.tap(), slot.netns()), ("bf3".to_owned(), "birdfeeder-3".to_owned()));
        assert_eq!(slot.netns_path(), PathBuf::from("/var/run/netns/birdfeeder-3"));
    }
}
