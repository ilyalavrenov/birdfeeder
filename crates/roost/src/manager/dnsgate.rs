//! The DNS gate's policy. A claimed guest with an FQDN allowlist can resolve its allowed names, and each answer's
//! addresses go into the session's FQDN set before the guest sees them.

use std::net::SocketAddr;

use guestnet::dnsgate::{self, DnsGate, Policy};

use super::*;

pub(super) struct Gate<D, H>(pub(super) Arc<Manager<D, H>>);

impl<D: Driver + 'static, H: Host> Policy for Gate<D, H> {
    /// Includes the generation too, so a new session in the same slot can't use the old one's answers.
    type Grant = SessionRef;

    fn grant(&self, client: Ipv4Addr, qname: &str) -> Option<Self::Grant> {
        let sessions = self.0.sessions();
        let s = sessions.by_name.values().find(|s| s.slot.guest == client)?;
        let allow = s.rec.fqdn_allowlist()?;
        dnsgate::fqdn_allowed(allow, qname).then(|| s.id.clone())
    }

    async fn program(&self, id: Self::Grant, addrs: BTreeMap<Ipv4Addr, u32>) -> Result<()> {
        self.0.program_fqdn(&id, addrs).await?;
        self.0.apply_net().await
    }
}

/// Binds the gate before the manager exists, so every ruleset points at the port it really holds.
pub(super) async fn bind_dns_gate(cfg: &Config, meter: &Meter) -> Result<(DnsGate, dnsgate::Config)> {
    let upstream = if let Some(upstream) = cfg.dns_upstream {
        upstream
    } else {
        let conf = fs::read_to_string("/etc/resolv.conf").context("dnsgate: read resolv.conf (set dns_upstream)")?;
        dnsgate::resolv_conf_upstream(&conf).context("dnsgate: no nameserver in resolv.conf (set dns_upstream)")?
    };
    let addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, cfg.dnsgate_port));
    let gate = DnsGate::bind(addr, meter).await.context("dnsgate listen")?;
    tracing::info!(addr = %gate.local_addr()?, %upstream, "dnsgate listening");
    Ok((gate, dnsgate::Config { upstream, min_ttl: cfg.fqdn_min_ttl_sec, max_ttl: cfg.fqdn_max_ttl_sec }))
}

impl<D: Driver + 'static, H: Host> Manager<D, H> {
    /// Admits `addrs` for their TTLs. Drops expired addresses first, then the ones expiring soonest if we're over the
    /// cap.
    ///
    /// Waits until they're durable, because the guest's resolver caches the answer and it should still reach what it
    /// was told after a restart. Lookups that arrive together share one write.
    pub(super) async fn program_fqdn(&self, id: &SessionRef, addrs: BTreeMap<Ipv4Addr, u32>) -> Result<(), Error> {
        let admitted = {
            let mut sessions = self.sessions();
            let s = sessions.get_mut(id).filter(|s| s.rec.fqdn_allowlist().is_some()).ok_or(Error::NotFound)?;
            let now = SystemTime::now();
            let known = &mut s.rec.fqdn_addrs;
            known.retain(|_, expires| *expires > now);
            known.extend(addrs.into_iter().map(|(ip, ttl)| (ip, now + Duration::from_secs(ttl.into()))));
            while known.len() > self.cfg.fqdn_max_ips as usize {
                let soonest = known.iter().min_by_key(|(_, expires)| **expires).map(|(ip, _)| *ip).expect("over the cap isn't empty");
                known.remove(&soonest);
            }
            self.store.stage(&s.rec)
        };
        persist_logged(admitted, &id.name, "persist fqdn addrs").await;
        Ok(())
    }
}
