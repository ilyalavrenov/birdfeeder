//! nftables rulesets, rendered for `nft -f`. The host ruleset routes and fences in every session, and each namespace
//! guards its own guest's frames.

use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::time::SystemTime;

use ipnet::Ipv4Net;

use crate::{GUEST_GATEWAY, GUEST_IP, GUEST_MAC, GUEST_TAP, NETNS_VETH, Session, Slot, tap_name};

/// What the host ruleset needs beyond the sessions.
#[derive(Debug, Clone, Copy)]
pub struct Host<'a> {
    /// The uplink guests masquerade out of.
    pub iface: &'a str,
    pub subnet: Ipv4Net,
    /// Where the DNS gate listens. Guests' port 53 gets redirected there.
    pub dns_port: u16,
    /// Every slot gets guard objects, live or not, so a freed slot's get deleted.
    pub slots: u32,
}

const GUARD_TABLE: &str = "birdfeeder_guard";
/// Rate-limits new connections to cap the kernel's O(n) conncount walk.
const GUARD_NEW_CONN_PER_SEC: u32 = 250;
const GUARD_LOG_SAMPLE: &str = "limit rate 1/minute burst 5 packets log prefix";
/// Matches every session's [`Slot::tap`].
const ANY_TAP: &str = "bf*";

/// The host ruleset. The session table gets replaced atomically. The guard table is edited in place so its connection
/// counts survive rebuilds and session churn can't reset them.
#[must_use]
pub fn host_ruleset(host: &Host, sessions: &[Session], now: SystemTime) -> String {
    let mut sessions = sessions.to_vec();
    sessions.sort_by_key(|s| s.slot.index);
    HostRuleset { host, sessions: &sessions, now }.to_string()
}

/// The host ruleset over sessions in slot order.
struct HostRuleset<'a> {
    host: &'a Host<'a>,
    sessions: &'a [Session<'a>],
    now: SystemTime,
}

impl Display for HostRuleset<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self { host, sessions, now } = *self;
        writeln!(f, "table inet birdfeeder\ndelete table inet birdfeeder\ntable inet birdfeeder {{")?;
        for s in sessions.iter().filter(|s| s.fqdn_active()) {
            fqdn_set(f, s, now)?;
        }
        dnat_chain(f, "prerouting", "type nat hook prerouting priority dstnat; policy accept;", Some(host.dns_port), sessions)?;
        dnat_chain(f, "output", "type nat hook output priority -100; policy accept;", None, sessions)?;

        writeln!(
            f,
            "  chain postrouting {{\n    type nat hook postrouting priority srcnat; policy accept;\n    oifname {:?} ip saddr {} masquerade\n  }}",
            host.iface,
            host.subnet.trunc(),
        )?;

        writeln!(f, "  chain forward {{\n    type filter hook forward priority filter; policy accept;")?;
        for s in sessions {
            writeln!(f, "    iifname {:?} jump {}", s.slot.tap(), s.chain())?;
        }
        writeln!(f, "    oifname {ANY_TAP:?} ct state new ct status & dnat == 0 drop\n  }}")?;

        for s in sessions {
            session_chain(f, s)?;
        }
        guest_input_chain(f, host.dns_port)?;
        writeln!(f, "}}")?;

        guard_table(f, host.slots, sessions)
    }
}

fn comma_separated<T: Display>(f: &mut Formatter<'_>, items: impl IntoIterator<Item = T>) -> fmt::Result {
    for (i, item) in items.into_iter().enumerate() {
        if i > 0 {
            f.write_str(", ")?;
        }
        write!(f, "{item}")?;
    }
    Ok(())
}

fn fqdn_set(f: &mut Formatter<'_>, s: &Session, now: SystemTime) -> fmt::Result {
    writeln!(f, "  set {} {{\n    type ipv4_addr\n    flags timeout", s.fqdn_set())?;
    let elems: Vec<String> = s
        .claim
        .map_or(&BTreeMap::new(), |c| c.fqdn_addrs)
        .iter()
        .filter_map(|(ip, expiry)| {
            let remaining = expiry.duration_since(now).ok().filter(|d| !d.is_zero())?;
            Some(format!("{ip} timeout {}s", remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0)))
        })
        .collect();
    if !elems.is_empty() {
        f.write_str("    elements = { ")?;
        comma_separated(f, &elems)?;
        writeln!(f, " }}")?;
    }
    writeln!(f, "  }}")
}

fn dnat_chain(f: &mut Formatter<'_>, name: &str, header: &str, dns_port: Option<u16>, sessions: &[Session]) -> fmt::Result {
    writeln!(f, "  chain {name} {{\n    {header}")?;
    for s in sessions {
        for e in s.claim.iter().flat_map(|c| c.endpoints.values()) {
            writeln!(f, "    fib daddr type local tcp dport {} dnat ip to {}:{}", e.host_port, s.slot.guest, e.guest_port)?;
        }
        if let Some(port) = dns_port.filter(|_| s.fqdn_active()) {
            writeln!(f, "    iifname {:?} meta l4proto {{ tcp, udp }} th dport 53 redirect to :{port}", s.slot.tap())?;
        }
    }
    writeln!(f, "  }}")
}

fn session_chain(f: &mut Formatter<'_>, s: &Session) -> fmt::Result {
    writeln!(
        f,
        "  chain {} {{\n    ct state established,related accept\n    oifname {ANY_TAP:?} drop\n    ip daddr 169.254.0.0/16 drop",
        s.chain()
    )?;
    let egress = s.egress();
    if !egress.is_some_and(|e| e.smtp_allowed) {
        writeln!(f, "    tcp dport {{ 25, 465, 587 }} drop")?;
    }
    if let Some(e) = egress.filter(|e| !e.cidr_allowlist.is_empty()) {
        f.write_str("    ip daddr { ")?;
        comma_separated(f, e.cidr_allowlist.iter().map(Ipv4Net::trunc))?;
        writeln!(f, " }} accept")?;
    }
    writeln!(f, "    ip daddr {{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }} drop")?;
    if s.fqdn_active() {
        writeln!(f, "    ip daddr @{} accept", s.fqdn_set())?;
    }
    writeln!(f, "    drop\n  }}")
}

fn guest_input_chain(f: &mut Formatter<'_>, dns_port: u16) -> fmt::Result {
    writeln!(
        f,
        "  chain input {{\n    type filter hook input priority filter; policy accept;\n    iifname {ANY_TAP:?} jump guest_input\n  }}"
    )?;
    writeln!(
        f,
        "  chain guest_input {{\n    ct state established,related accept\n    icmp type echo-request accept\n    meta l4proto {{ tcp, udp }} th dport {dns_port} accept\n    counter drop\n  }}"
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Chain,
    Set,
    Counter,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Chain => "chain",
            Self::Set => "set",
            Self::Counter => "counter",
        }
    }
}

const DROP_KINDS: [&str; 4] = ["spoof", "v6", "ctrate", "ctcap"];

fn guard_table(f: &mut Formatter<'_>, slots: u32, sessions: &[Session]) -> fmt::Result {
    let t = format!("inet {GUARD_TABLE}");
    writeln!(f, "add table {t}")?;
    writeln!(f, "add chain {t} prerouting {{ type filter hook prerouting priority mangle; policy accept; }}")?;
    writeln!(f, "flush chain {t} prerouting")?;
    for kind in DROP_KINDS {
        writeln!(f, "add chain {t} drop_{kind}\nflush chain {t} drop_{kind}")?;
        writeln!(f, "add rule {t} drop_{kind} {GUARD_LOG_SAMPLE} \"{GUARD_TABLE} {kind}: \"")?;
        writeln!(f, "add rule {t} drop_{kind} drop")?;
    }

    let live: BTreeMap<u32, &Session> = sessions.iter().map(|s| (s.slot.index, s)).collect();
    let mut dispatch = Vec::new();
    for index in 0..slots {
        let tap = tap_name(index);
        // chains first: their rules pin the sets and counters, which can't be deleted while something references them.
        let objs = [
            (Kind::Chain, format!("guard_{tap}"), ""),
            (Kind::Set, format!("ct_{tap}"), " { type ipv4_addr; flags dynamic; size 8; }"),
            (Kind::Counter, format!("spoof_{tap}"), ""),
            (Kind::Counter, format!("v6_{tap}"), ""),
            (Kind::Counter, format!("ctrate_{tap}"), ""),
            (Kind::Counter, format!("ctcap_{tap}"), ""),
        ];

        let Some(s) = live.get(&index) else {
            // nft only deletes what exists, so add each object first.
            for (kind, name, def) in &objs {
                let kind = kind.as_str();
                writeln!(f, "add {kind} {t} {name}{def}\ndelete {kind} {t} {name}")?;
            }
            continue;
        };

        for (kind, name, def) in &objs {
            writeln!(f, "add {} {t} {name}{def}", kind.as_str())?;
            if *kind == Kind::Chain {
                writeln!(f, "flush chain {t} {name}")?;
            }
        }
        let rule = format!("add rule {t} guard_{tap} ");
        writeln!(f, "{rule}meta nfproto ipv6 counter name v6_{tap} goto drop_v6")?;
        // host multicast has to skip the guest source-address checks.
        writeln!(f, "{rule}ip daddr {{ 224.0.0.0/4, 255.255.255.255 }} return")?;
        writeln!(f, "{rule}ip saddr != {} counter name spoof_{tap} goto drop_spoof", s.slot.guest)?;
        if let Some(limit) = s.conn_limit {
            writeln!(
                f,
                "{rule}ct state new limit rate over {GUARD_NEW_CONN_PER_SEC}/second burst {limit} packets counter name ctrate_{tap} goto drop_ctrate"
            )?;
            writeln!(f, "{rule}ct state new add @ct_{tap} {{ ip saddr ct count over {limit} }} counter name ctcap_{tap} goto drop_ctcap")?;
        }
        dispatch.push(format!("{tap:?} : jump guard_{tap}"));
    }
    if !dispatch.is_empty() {
        write!(f, "add rule {t} prerouting iifname vmap {{ ")?;
        comma_separated(f, &dispatch)?;
        writeln!(f, " }}")?;
    }
    Ok(())
}

const NETNS_TABLE: &str = "birdfeeder";

/// The ruleset inside a session's namespace: NAT between [`GUEST_IP`] and the slot's address, plus the guest frame
/// guards. Those live here because non-init namespaces can't use `nf_log`.
#[must_use]
pub fn netns_ruleset(slot: &Slot) -> String {
    NetnsRuleset(slot).to_string()
}

struct NetnsRuleset<'a>(&'a Slot);

impl Display for NetnsRuleset<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let (guest, gateway) = (self.0.guest, self.0.gateway);
        for family in ["inet", "arp"] {
            writeln!(f, "table {family} {NETNS_TABLE}\ndelete table {family} {NETNS_TABLE}")?;
        }
        // the guest's resolver is its gateway, which is local to this namespace. So DNS has to be forwarded to the host
        // end of the veth, where the host ruleset redirects it to the DNS gate.
        write!(
            f,
            "table inet {NETNS_TABLE} {{
  counter v6 {{ }}
  counter spoof {{ }}
  counter leak {{ }}
  chain prerouting {{
    type nat hook prerouting priority dstnat; policy accept;
    iifname {NETNS_VETH:?} ip daddr {guest} dnat ip to {GUEST_IP}
    iifname {GUEST_TAP:?} ip daddr {GUEST_GATEWAY} meta l4proto {{ tcp, udp }} th dport 53 dnat ip to {gateway}
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    oifname {NETNS_VETH:?} ip saddr {GUEST_IP} snat ip to {guest}
  }}
"
        )?;
        // after srcnat (100): conntrack skips nat on invalid packets (late rsts), and those must not leave with the
        // guest's address.
        write!(
            f,
            "  chain egress {{
    type filter hook postrouting priority 150; policy accept;
    oifname {NETNS_VETH:?} ip saddr != {guest} counter name leak drop
  }}
  chain guard {{
    type filter hook prerouting priority mangle; policy accept;
    iifname != {GUEST_TAP:?} accept
    meta nfproto ipv6 counter name v6 drop
    ip daddr {{ 224.0.0.0/4, 255.255.255.255 }} accept
    ether saddr != {GUEST_MAC} counter name spoof drop
    ip saddr != {GUEST_IP} counter name spoof drop
  }}
}}
table arp {NETNS_TABLE} {{
  counter spoof {{ }}
  chain input {{
    type filter hook input priority filter; policy accept;
    iifname != {GUEST_TAP:?} accept
    ether saddr != {GUEST_MAC} counter name spoof drop
    arp saddr ether != {GUEST_MAC} counter name spoof drop
    arp saddr ip != {GUEST_IP} counter name spoof drop
  }}
}}
"
        )
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::num::NonZeroU32;
    use std::time::Duration;

    use rstest::{fixture, rstest};

    use super::*;
    use crate::{Claim, Egress, Endpoint};

    const HOST: Host = Host { iface: "eth0", subnet: Ipv4Net::new_assert(Ipv4Addr::new(172, 20, 0, 0), 24), dns_port: 15353, slots: 3 };

    fn slot(index: u32) -> Slot {
        Slot::new(HOST.subnet, index).unwrap()
    }

    fn guard_rules(ruleset: &str, tap: &str) -> Vec<String> {
        let prefix = format!("add rule inet birdfeeder_guard guard_{tap} ");
        ruleset.lines().filter_map(|l| l.trim().strip_prefix(&prefix)).map(str::to_owned).collect()
    }

    fn index(ruleset: &str, needle: &str) -> usize {
        ruleset.find(needle).unwrap_or_else(|| panic!("{needle:?} not in ruleset"))
    }

    /// A ruleset with only the middle of [`HOST`]'s three slots live.
    #[fixture]
    fn live_slot_1() -> String {
        let endpoints = BTreeMap::from([("http".to_owned(), Endpoint { host_port: 31001, guest_port: 6000 })]);
        let claim = Claim { endpoints: &endpoints, egress: None, fqdn_addrs: &BTreeMap::new() };
        let s = Session { name: "python312-1", slot: slot(1), conn_limit: NonZeroU32::new(4096), claim: Some(claim) };
        host_ruleset(&HOST, &[s], SystemTime::now())
    }

    #[rstest]
    fn guard_tables_cover_a_live_slot(#[from(live_slot_1)] ruleset: String) {
        assert!(index(&ruleset, "delete table inet birdfeeder\n") < index(&ruleset, "add table inet birdfeeder_guard\n"));
        assert!(
            ruleset
                .contains("add chain inet birdfeeder_guard prerouting { type filter hook prerouting priority mangle; policy accept; }\n")
        );
        assert!(ruleset.contains("add set inet birdfeeder_guard ct_bf1 { type ipv4_addr; flags dynamic; size 8; }\n"));
        assert!(!ruleset.contains("delete set inet birdfeeder_guard ct_bf1\n"));
        assert_eq!(
            guard_rules(&ruleset, "bf1"),
            [
                "meta nfproto ipv6 counter name v6_bf1 goto drop_v6",
                "ip daddr { 224.0.0.0/4, 255.255.255.255 } return",
                "ip saddr != 172.20.0.6 counter name spoof_bf1 goto drop_spoof",
                "ct state new limit rate over 250/second burst 4096 packets counter name ctrate_bf1 goto drop_ctrate",
                "ct state new add @ct_bf1 { ip saddr ct count over 4096 } counter name ctcap_bf1 goto drop_ctcap",
            ]
        );
        assert!(ruleset.contains("add rule inet birdfeeder_guard prerouting iifname vmap { \"bf1\" : jump guard_bf1 }\n"));
        assert!(ruleset.contains("    fib daddr type local tcp dport 31001 dnat ip to 172.20.0.6:6000\n"));
        assert!(ruleset.contains(
            "add rule inet birdfeeder_guard drop_ctcap limit rate 1/minute burst 5 packets log prefix \"birdfeeder_guard ctcap: \"\n"
        ));
        assert!(ruleset.contains("add rule inet birdfeeder_guard drop_ctcap drop\n"));
    }

    #[rstest]
    #[case::below_the_live_slot("bf0")]
    #[case::above_the_live_slot("bf2")]
    fn guard_tables_delete_a_free_slots_objects(#[from(live_slot_1)] ruleset: String, #[case] tap: &str) {
        assert!(!ruleset.contains(&format!("jump guard_{tap}")));
        assert_eq!(guard_rules(&ruleset, tap), Vec::<String>::new());
        let delete_set = index(&ruleset, &format!("delete set inet birdfeeder_guard ct_{tap}\n"));
        assert!(index(&ruleset, &format!("delete chain inet birdfeeder_guard guard_{tap}\n")) < delete_set);
        assert!(index(&ruleset, &format!("add set inet birdfeeder_guard ct_{tap} {{")) < delete_set);
        assert!(ruleset.contains(&format!("delete counter inet birdfeeder_guard ctcap_{tap}\n")));
    }

    #[test]
    fn guard_conn_limit_is_optional() {
        let off = Session { name: "a-0", slot: slot(0), conn_limit: None, claim: None };
        let capped = Session { name: "a-1", slot: slot(1), conn_limit: NonZeroU32::new(4096), claim: None };

        // out of slot order: the dispatch map still lists bf0 first.
        let ruleset = host_ruleset(&Host { slots: 2, ..HOST }, &[capped, off], SystemTime::now());

        assert_eq!(guard_rules(&ruleset, "bf0").len(), 3);
        assert!(!ruleset.contains("ctcap_bf0 goto"));
        assert!(ruleset.contains("ct count over 4096 } counter name ctcap_bf1 goto drop_ctcap\n"));
        assert!(ruleset.contains("iifname vmap { \"bf0\" : jump guard_bf0, \"bf1\" : jump guard_bf1 }"));
    }

    #[test]
    fn guest_input_admits_only_the_dns_gate() {
        let ruleset = host_ruleset(&Host { slots: 1, ..HOST }, &[], SystemTime::now());

        assert!(ruleset.contains(
            "  chain input {\n    type filter hook input priority filter; policy accept;\n    iifname \"bf*\" jump guest_input\n  }\n"
        ));
        assert!(ruleset.contains(
            "  chain guest_input {\n    ct state established,related accept\n    icmp type echo-request accept\n    meta l4proto { tcp, udp } th dport 15353 accept\n    counter drop\n  }\n"
        ));
    }

    #[test]
    fn session_chains_follow_the_claim() {
        let now = SystemTime::now();
        let endpoints = BTreeMap::from([
            ("http".to_owned(), Endpoint { host_port: 31000, guest_port: 8080 }),
            ("admin".to_owned(), Endpoint { host_port: 31001, guest_port: 9090 }),
        ]);
        let egress = Egress {
            cidr_allowlist: vec!["1.1.1.7/24".parse().unwrap(), "8.8.8.8/32".parse().unwrap()],
            fqdn_allowlist: vec!["example.com".parse().unwrap()],
            smtp_allowed: true,
        };
        let fqdn_addrs = BTreeMap::from([
            (Ipv4Addr::new(93, 184, 215, 14), now + Duration::from_millis(2500)),
            (Ipv4Addr::new(93, 184, 215, 15), now - Duration::from_secs(1)),
        ]);
        let claim = Claim { endpoints: &endpoints, egress: Some(&egress), fqdn_addrs: &fqdn_addrs };
        let claimed = Session { name: "py.3-1", slot: slot(1), conn_limit: None, claim: Some(claim) };
        let pooled = Session { name: "py-2", slot: slot(2), conn_limit: None, claim: None };

        let ruleset = host_ruleset(&HOST, &[claimed, pooled], now);

        assert!(ruleset.contains(
            "  set sess_py_3_1_fqdn {\n    type ipv4_addr\n    flags timeout\n    elements = { 93.184.215.14 timeout 3s }\n  }\n"
        ));
        assert!(!ruleset.contains("sess_py_2_fqdn"));
        // endpoints in name order, and the DNS redirect only in prerouting.
        let prerouting = "  chain prerouting {\n    type nat hook prerouting priority dstnat; policy accept;\n    fib daddr type local tcp dport 31001 dnat ip to 172.20.0.6:9090\n    fib daddr type local tcp dport 31000 dnat ip to 172.20.0.6:8080\n    iifname \"bf1\" meta l4proto { tcp, udp } th dport 53 redirect to :15353\n  }\n";
        assert!(ruleset.contains(prerouting));
        assert!(ruleset.contains("  chain output {\n    type nat hook output priority -100; policy accept;\n    fib daddr type local tcp dport 31001 dnat ip to 172.20.0.6:9090\n    fib daddr type local tcp dport 31000 dnat ip to 172.20.0.6:8080\n  }\n"));
        assert!(ruleset.contains("    oifname \"eth0\" ip saddr 172.20.0.0/24 masquerade\n"));
        assert!(ruleset.contains("    iifname \"bf1\" jump sess_py_3_1\n    iifname \"bf2\" jump sess_py_2\n    oifname \"bf*\" ct state new ct status & dnat == 0 drop\n"));
        assert!(ruleset.contains(
            "  chain sess_py_3_1 {\n    ct state established,related accept\n    oifname \"bf*\" drop\n    ip daddr 169.254.0.0/16 drop\n    ip daddr { 1.1.1.0/24, 8.8.8.8/32 } accept\n    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } drop\n    ip daddr @sess_py_3_1_fqdn accept\n    drop\n  }\n"
        ));
        assert!(ruleset.contains(
            "  chain sess_py_2 {\n    ct state established,related accept\n    oifname \"bf*\" drop\n    ip daddr 169.254.0.0/16 drop\n    tcp dport { 25, 465, 587 } drop\n    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } drop\n    drop\n  }\n"
        ));
    }

    #[test]
    fn netns_ruleset_nats_and_guards_the_guest() {
        let ruleset = netns_ruleset(&slot(1));

        assert!(
            ruleset.starts_with("table inet birdfeeder\ndelete table inet birdfeeder\ntable arp birdfeeder\ndelete table arp birdfeeder\n")
        );
        assert!(ruleset.contains(
            "  chain prerouting {\n    type nat hook prerouting priority dstnat; policy accept;\n    iifname \"wv\" ip daddr 172.20.0.6 dnat ip to 172.16.0.2\n    iifname \"tap0\" ip daddr 172.16.0.1 meta l4proto { tcp, udp } th dport 53 dnat ip to 172.20.0.5\n  }\n"
        ));
        assert!(ruleset.contains(
            "  chain postrouting {\n    type nat hook postrouting priority srcnat; policy accept;\n    oifname \"wv\" ip saddr 172.16.0.2 snat ip to 172.20.0.6\n  }\n"
        ));
        assert!(ruleset.contains(
            "  chain egress {\n    type filter hook postrouting priority 150; policy accept;\n    oifname \"wv\" ip saddr != 172.20.0.6 counter name leak drop\n  }\n"
        ));
        assert!(ruleset.contains(
            "  chain guard {\n    type filter hook prerouting priority mangle; policy accept;\n    iifname != \"tap0\" accept\n    meta nfproto ipv6 counter name v6 drop\n    ip daddr { 224.0.0.0/4, 255.255.255.255 } accept\n    ether saddr != 06:00:ac:10:00:02 counter name spoof drop\n    ip saddr != 172.16.0.2 counter name spoof drop\n  }\n"
        ));
        assert!(ruleset.contains(
            "table arp birdfeeder {\n  counter spoof { }\n  chain input {\n    type filter hook input priority filter; policy accept;\n    iifname != \"tap0\" accept\n    ether saddr != 06:00:ac:10:00:02 counter name spoof drop\n    arp saddr ether != 06:00:ac:10:00:02 counter name spoof drop\n    arp saddr ip != 172.16.0.2 counter name spoof drop\n  }\n}\n"
        ));
        assert!(!ruleset.contains("log "));
    }
}
