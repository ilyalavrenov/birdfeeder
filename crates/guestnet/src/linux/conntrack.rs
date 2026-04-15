//! Flushes a guest address's conntrack flows. Slot addresses get reused, and a retired guest's flows mustn't hand the
//! next guest established traffic.
//!
//! ctnetlink deletes one flow per request by its tuple, so we dump the table and delete each match. We only parse flows
//! far enough to match them and send them back verbatim, so any attribute we don't know about stays intact.

use std::io;
use std::net::Ipv4Addr;

use anyhow::Context as _;
use rtnetlink::sys::protocols::NETLINK_NETFILTER;
use rtnetlink::sys::{Socket, SocketAddr};

const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const IPCTNL_MSG_CT_GET: u16 = 1;
const IPCTNL_MSG_CT_DELETE: u16 = 2;
const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_ZONE: u16 = 18;
const CTA_TUPLE_IP: u16 = 1;
const CTA_IP_V4_SRC: u16 = 1;
/// Strips `NLA_F_NESTED` and `NLA_F_NET_BYTEORDER`.
const NLA_TYPE_MASK: u16 = 0x3fff;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_HDRLEN: usize = 16;
const NFGENMSG_LEN: usize = 4;

/// Caps retries of a dump that got interrupted by a concurrent table update.
const DUMP_ATTEMPTS: usize = 3;

pub(super) async fn delete(guest: Ipv4Addr) -> anyhow::Result<()> {
    tokio::task::spawn_blocking(move || delete_blocking(guest))
        .await
        .context("conntrack task")?
        .with_context(|| format!("delete conntrack {guest}"))
}

fn delete_blocking(guest: Ipv4Addr) -> io::Result<()> {
    let mut sock = Socket::new(NETLINK_NETFILTER)?;
    sock.bind_auto()?;
    sock.connect(&SocketAddr::new(0, 0))?;

    // an interrupted dump might have skipped flows, so only a complete pass counts.
    let mut flows = None;
    for _ in 0..DUMP_ATTEMPTS {
        flows = dump(&sock)?;
        if flows.is_some() {
            break;
        }
    }
    let flows = flows.ok_or_else(|| io::Error::other("conntrack dump interrupted every attempt"))?;

    for flow in flows.iter().filter(|f| f.involves(guest)) {
        sock.send(&request(IPCTNL_MSG_CT_DELETE, NLM_F_ACK, &flow.key), 0)?;
        let (reply, _) = sock.recv_from_full()?;
        for (kind, _, payload) in messages(&reply) {
            match (kind, errno(payload)) {
                // a flow that expired after the dump is already gone.
                (NLMSG_ERROR, Some(0 | libc::ENOENT)) => {}
                (NLMSG_ERROR, Some(code)) => return Err(io::Error::from_raw_os_error(code)),
                _ => {}
            }
        }
    }
    Ok(())
}

/// One full table dump, or `None` if a concurrent update interrupted it.
fn dump(sock: &Socket) -> io::Result<Option<Vec<Flow>>> {
    sock.send(&request(IPCTNL_MSG_CT_GET, NLM_F_DUMP, &[]), 0)?;
    let (mut flows, mut interrupted) = (Vec::new(), false);
    loop {
        let (buf, _) = sock.recv_from_full()?;
        for (kind, flags, payload) in messages(&buf) {
            interrupted |= flags & NLM_F_DUMP_INTR != 0;
            match kind {
                NLMSG_DONE => return Ok((!interrupted).then_some(flows)),
                NLMSG_ERROR => return Err(io::Error::from_raw_os_error(errno(payload).unwrap_or(libc::EIO))),
                _ => flows.extend(payload.get(NFGENMSG_LEN..).map(Flow::parse)),
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Flow {
    orig_src: Option<Ipv4Addr>,
    reply_src: Option<Ipv4Addr>,
    /// The raw attributes ctnetlink uses to look up a flow: its original tuple and zone.
    key: Vec<u8>,
}

impl Flow {
    fn parse(attrs: &[u8]) -> Self {
        let mut flow = Self { orig_src: None, reply_src: None, key: Vec::new() };
        for (kind, value, raw) in nlas(attrs) {
            match kind {
                CTA_TUPLE_ORIG => flow.orig_src = tuple_src(value),
                CTA_TUPLE_REPLY => flow.reply_src = tuple_src(value),
                _ => {}
            }
            if matches!(kind, CTA_TUPLE_ORIG | CTA_ZONE) {
                flow.key.extend_from_slice(raw);
                flow.key.resize(align(flow.key.len()), 0);
            }
        }
        flow
    }

    /// A guest's own connections leave with its address as the source. Inbound ones to its endpoints come back from it.
    fn involves(&self, guest: Ipv4Addr) -> bool {
        self.orig_src == Some(guest) || self.reply_src == Some(guest)
    }
}

fn tuple_src(tuple: &[u8]) -> Option<Ipv4Addr> {
    let (_, ip, _) = nlas(tuple).find(|(kind, ..)| *kind == CTA_TUPLE_IP)?;
    let (_, src, _) = nlas(ip).find(|(kind, ..)| *kind == CTA_IP_V4_SRC)?;
    Some(Ipv4Addr::from(<[u8; 4]>::try_from(src).ok()?))
}

/// A ctnetlink request for IPv4 flows.
fn request(kind: u16, flags: u16, attrs: &[u8]) -> Vec<u8> {
    let len = NLMSG_HDRLEN + NFGENMSG_LEN + attrs.len();
    let mut msg = Vec::with_capacity(len);
    msg.extend_from_slice(&u32::try_from(len).expect("a request fits a netlink message").to_ne_bytes());
    msg.extend_from_slice(&(NFNL_SUBSYS_CTNETLINK << 8 | kind).to_ne_bytes());
    msg.extend_from_slice(&(NLM_F_REQUEST | flags).to_ne_bytes());
    // seq and pid: only one request is in flight at a time, so we don't need to match replies up.
    msg.extend_from_slice(&[0; 8]);
    // nfgenmsg: family, NFNETLINK_V0, res_id.
    msg.extend_from_slice(&[libc::AF_INET as u8, 0, 0, 0]);
    msg.extend_from_slice(attrs);
    msg
}

/// A netlink buffer's messages as (type, flags, payload).
fn messages(buf: &[u8]) -> impl Iterator<Item = (u16, u16, &[u8])> {
    let mut off = 0;
    std::iter::from_fn(move || {
        let header = buf.get(off..off + NLMSG_HDRLEN)?;
        let len = u32::from_ne_bytes(header[..4].try_into().ok()?) as usize;
        let payload = buf.get(off + NLMSG_HDRLEN..off + len)?;
        off += align(len.max(NLMSG_HDRLEN));
        Some((u16::from_ne_bytes([header[4], header[5]]), u16::from_ne_bytes([header[6], header[7]]), payload))
    })
}

/// An `NLMSG_ERROR`'s errno, 0 for an ack.
fn errno(payload: &[u8]) -> Option<i32> {
    Some(-i32::from_ne_bytes(payload.get(..4)?.try_into().ok()?))
}

/// Attributes as (type, value, raw bytes with header).
fn nlas(buf: &[u8]) -> impl Iterator<Item = (u16, &[u8], &[u8])> {
    let mut off = 0;
    std::iter::from_fn(move || {
        let header = buf.get(off..off + 4)?;
        let len = usize::from(u16::from_ne_bytes([header[0], header[1]]));
        let raw = buf.get(off..off + len).filter(|_| len >= 4)?;
        off += align(len);
        Some((u16::from_ne_bytes([header[2], header[3]]) & NLA_TYPE_MASK, &raw[4..], raw))
    })
}

const fn align(len: usize) -> usize {
    (len + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nla(kind: u16, value: &[u8]) -> Vec<u8> {
        let len = u16::try_from(4 + value.len()).unwrap();
        let mut out = [len.to_ne_bytes(), kind.to_ne_bytes()].concat();
        out.extend_from_slice(value);
        out.resize(align(out.len()), 0);
        out
    }

    fn tuple(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        const NESTED: u16 = 1 << 15;
        let ip = [nla(CTA_IP_V4_SRC, &src), nla(2, &dst)].concat();
        // the proto tuple just rides along in the key.
        [nla(CTA_TUPLE_IP | NESTED, &ip), nla(2 | NESTED, &nla(1, &[17]))].concat()
    }

    #[test]
    fn flows_match_either_direction_and_keep_their_key() {
        let orig = nla(CTA_TUPLE_ORIG | 1 << 15, &tuple([172, 20, 0, 6], [1, 1, 1, 1]));
        let zone = nla(CTA_ZONE, &7_u16.to_be_bytes());
        let attrs =
            [orig.clone(), nla(CTA_TUPLE_REPLY | 1 << 15, &tuple([1, 1, 1, 1], [10, 0, 0, 1])), nla(3, &[0, 0, 0, 8]), zone.clone()]
                .concat();

        let flow = Flow::parse(&attrs);
        assert_eq!(
            flow,
            Flow { orig_src: Some(Ipv4Addr::new(172, 20, 0, 6)), reply_src: Some(Ipv4Addr::new(1, 1, 1, 1)), key: [orig, zone].concat() }
        );
        assert!(flow.involves(Ipv4Addr::new(172, 20, 0, 6)));
        assert!(flow.involves(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!flow.involves(Ipv4Addr::new(10, 0, 0, 1)));

        // a truncated attribute ends the walk instead of reading past it.
        assert_eq!(Flow::parse(&attrs[..9]).orig_src, None);
    }

    #[test]
    fn messages_split_a_buffer() {
        let msg = request(IPCTNL_MSG_CT_DELETE, NLM_F_ACK, &nla(CTA_ZONE, &[0, 1]));
        let buf = [msg.clone(), msg].concat();
        let parsed: Vec<_> = messages(&buf).collect();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, NFNL_SUBSYS_CTNETLINK << 8 | IPCTNL_MSG_CT_DELETE);
        assert_eq!(parsed[0].1, NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(&parsed[0].2[NFGENMSG_LEN..], nla(CTA_ZONE, &[0, 1]));
    }
}
