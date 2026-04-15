//! The session API over gRPC.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use guestnet::Egress;
use guestnet::dnsgate::FqdnPattern;
use ipnet::{IpNet, Ipv4Net};
use roost_api::RequestError;
use roost_api::v1::roost_service_server::RoostService;
use roost_api::v1::{
    ClaimSessionRequest, ClaimSessionResponse, DeleteSessionRequest, DeleteSessionResponse, GetSessionRequest, GetSessionResponse,
    HostStatusRequest, HostStatusResponse, ListSessionsRequest, ListSessionsResponse, PoolFill, Session, SessionState,
    SetSessionExpiryRequest, SetSessionExpiryResponse,
};
use sha2::{Digest as _, Sha256};
use tonic::{Request, Response, Status};
use tracing::Instrument as _;
use vmm::Driver;

use crate::host::Host;
use crate::manager::{Claim, Error, Info, Keyed, Manager};
use crate::state::{ClaimKey, Released, State};

pub struct Api<D, H>(pub Arc<Manager<D, H>>);

#[tonic::async_trait]
impl<D: Driver + 'static, H: Host> RoostService for Api<D, H> {
    async fn claim_session(&self, req: Request<ClaimSessionRequest>) -> Result<Response<ClaimSessionResponse>, Status> {
        let claim = Claim::try_from(req.into_inner())?;
        let m = Arc::clone(&self.0);
        let info = detached(async move { m.claim(claim).await }).await?;
        Ok(Response::new(ClaimSessionResponse { session: Some(session(info)) }))
    }

    async fn delete_session(&self, req: Request<DeleteSessionRequest>) -> Result<Response<DeleteSessionResponse>, Status> {
        let DeleteSessionRequest { name, generation } = req.into_inner();
        let m = Arc::clone(&self.0);
        detached(async move { m.delete(&name, generation).await }).await?;
        Ok(Response::new(DeleteSessionResponse {}))
    }

    async fn get_session(&self, req: Request<GetSessionRequest>) -> Result<Response<GetSessionResponse>, Status> {
        let msg = req.into_inner();
        roost_api::validate_get(&msg)?;
        let found = if msg.name.is_empty() {
            match self.0.get_keyed(&msg.idempotency_key).await? {
                Keyed::Live(info) => session(info),
                Keyed::Deleted(released) => deleted(released, &self.0.config().host_id),
            }
        } else {
            session(self.0.get(&msg.name)?)
        };
        Ok(Response::new(GetSessionResponse { session: Some(found) }))
    }

    async fn list_sessions(&self, req: Request<ListSessionsRequest>) -> Result<Response<ListSessionsResponse>, Status> {
        let msg = req.into_inner();
        roost_api::validate_list(&msg)?;
        Ok(Response::new(ListSessionsResponse { sessions: self.0.list(&msg.labels).into_iter().map(session).collect() }))
    }

    async fn set_session_expiry(&self, req: Request<SetSessionExpiryRequest>) -> Result<Response<SetSessionExpiryResponse>, Status> {
        let SetSessionExpiryRequest { name, generation, expires_at_ms } = req.into_inner();
        roost_api::validate_expiry(expires_at_ms)?;
        let expires_at = (expires_at_ms != 0).then(|| UNIX_EPOCH + Duration::from_millis(expires_at_ms.cast_unsigned()));
        self.0.set_expiry(&name, generation, expires_at).await?;
        Ok(Response::new(SetSessionExpiryResponse {}))
    }

    async fn host_status(&self, _: Request<HostStatusRequest>) -> Result<Response<HostStatusResponse>, Status> {
        let s = self.0.status();
        let int = |n: u32| i32::try_from(n).unwrap_or(i32::MAX);
        Ok(Response::new(HostStatusResponse {
            capacity: int(s.capacity),
            running: int(s.running),
            pools: s
                .pools
                .into_iter()
                .map(|p| PoolFill { template_id: p.template_id, ready: int(p.ready), target: int(p.target), fingerprint: p.fingerprint })
                .collect(),
            max_vcpus: int(s.max_vcpus),
            reserved_vcpus: int(s.reserved_vcpus),
            max_memory_mib: int(s.max_memory_mib),
            reserved_memory_mib: int(s.reserved_memory_mib),
        }))
    }
}

/// Runs a mutation to the end even if the caller hangs up, so a dropped call can't leave it half done.
async fn detached<T: Send + 'static>(op: impl Future<Output = Result<T, Error>> + Send + 'static) -> Result<T, Status> {
    Ok(tokio::spawn(op.instrument(tracing::Span::current())).await.map_err(|err| Status::internal(err.to_string()))??)
}

impl From<Error> for Status {
    fn from(err: Error) -> Self {
        match err {
            Error::NotFound => Self::not_found(err.to_string()),
            Error::PoolEmpty | Error::SlotsExhausted => Self::resource_exhausted(err.to_string()),
            Error::UnknownTemplate => Self::invalid_argument(err.to_string()),
            Error::GenerationMismatch | Error::KeyReused | Error::KeyDeleted => Self::failed_precondition(err.to_string()),
            Error::Busy => Self::unavailable(err.to_string()),
            Error::Internal(err) => Self::internal(format!("{err:#}")),
        }
    }
}

/// The claim a request asks for, with its CIDRs, idle timeout and FQDN patterns parsed.
impl TryFrom<ClaimSessionRequest> for Claim {
    type Error = RequestError;

    fn try_from(msg: ClaimSessionRequest) -> Result<Self, RequestError> {
        roost_api::validate_claim(&msg)?;
        let key = (!msg.idempotency_key.is_empty()).then(|| ClaimKey { key: msg.idempotency_key.clone(), digest: digest(&msg) });
        let ClaimSessionRequest { template_id, labels, egress, idle_timeout_ms, idempotency_key: _ } = msg;
        let egress = egress
            .map(|e| {
                Ok::<_, RequestError>(Egress {
                    cidr_allowlist: e.cidr_allowlist.iter().map(|c| cidr(c)).collect::<Result<_, _>>()?,
                    fqdn_allowlist: e
                        .fqdn_allowlist
                        .into_iter()
                        .map(|d| FqdnPattern::try_from(d).map_err(|_| RequestError::Fqdn))
                        .collect::<Result<_, _>>()?,
                    smtp_allowed: e.smtp_allowed,
                })
            })
            .transpose()?;
        Ok(Self {
            template_id,
            labels,
            egress,
            idle_timeout: u64::try_from(idle_timeout_ms).ok().filter(|ms| *ms > 0).map(Duration::from_millis),
            key,
        })
    }
}

/// An IPv4 prefix or bare address, masked to its network.
fn cidr(entry: &str) -> Result<Ipv4Net, RequestError> {
    match entry.parse::<IpNet>().or_else(|_| entry.parse::<IpAddr>().map(IpNet::from)) {
        Ok(IpNet::V4(net)) => Ok(net.trunc()),
        Ok(IpNet::V6(_)) => Err(RequestError::Ipv6Egress),
        Err(_) => Err(RequestError::Cidr(entry.to_owned())),
    }
}

fn session(info: Info) -> Session {
    let state = match info.state {
        State::Booting => SessionState::Booting,
        State::Pooled => SessionState::Pooled,
        State::Claimed => SessionState::Claimed,
        State::Stopping => SessionState::Stopping,
    };
    Session {
        name: info.name,
        endpoints: info.endpoints,
        generation: info.generation,
        state: state.into(),
        host_id: info.host_id,
        template_id: info.template_id,
        labels: info.labels,
    }
}

fn deleted(r: Released, host_id: &str) -> Session {
    Session {
        name: r.name,
        endpoints: BTreeMap::new(),
        generation: r.generation,
        state: SessionState::Deleted.into(),
        host_id: host_id.to_owned(),
        template_id: r.template_id,
        labels: r.labels,
    }
}

/// Fingerprints a claim request by its content. The JSON encoding writes maps in key order, so equal requests encode
/// the same.
fn digest(msg: &ClaimSessionRequest) -> String {
    hex::encode(Sha256::digest(serde_json::to_vec(msg).expect("claims encode")))
}

#[cfg(test)]
mod tests {
    use roost_api::v1::EgressPolicy;
    use rstest::rstest;

    use super::*;
    use crate::testing::{FakeDriver, FakeHost};

    fn egress_request(cidrs: &[&str], fqdns: &[&str]) -> ClaimSessionRequest {
        ClaimSessionRequest {
            template_id: "web-v1".into(),
            egress: Some(EgressPolicy {
                cidr_allowlist: cidrs.iter().map(ToString::to_string).collect(),
                fqdn_allowlist: fqdns.iter().map(ToString::to_string).collect(),
                smtp_allowed: true,
            }),
            ..ClaimSessionRequest::default()
        }
    }

    #[test]
    fn claim_request_parses() {
        let mut request = egress_request(&["8.8.8.8", "1.2.3.4/24"], &["*.example.com"]);
        request.idle_timeout_ms = 1500;
        let claim = Claim::try_from(request).unwrap();
        let egress = claim.egress.unwrap();
        assert_eq!(egress.cidr_allowlist, ["8.8.8.8/32".parse::<Ipv4Net>().unwrap(), "1.2.3.0/24".parse().unwrap()]);
        assert_eq!(egress.fqdn_allowlist, [FqdnPattern::Wildcard("example.com".into())]);
        assert!(egress.smtp_allowed);
        assert_eq!((claim.idle_timeout, claim.key), (Some(Duration::from_millis(1500)), None));
    }

    #[rstest]
    #[case::nft_brace("1.1.1.0/24 } accept")]
    #[case::nft_statement("1.1.1.0/24; add rule inet roost forward accept")]
    #[case::bare_brace("}")]
    #[case::newline("1.1.1.0/24\nadd rule")]
    #[case::ipv6_address("::1")]
    #[case::ipv6_prefix("2001:db8::/32")]
    #[case::prefix_too_long("10.0.0.0/33")]
    #[case::word("evil")]
    #[case::empty("")]
    fn hostile_cidrs_are_refused(#[case] hostile: &str) {
        let err = Status::from(Claim::try_from(egress_request(&[hostile], &[])).unwrap_err());
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn keyed_claims_over_the_api() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = crate::testing::config_json(dir.path());
        cfg["templates"][0]["pool_target"] = 2.into();
        let m = Manager::start(
            serde_json::from_value(cfg).unwrap(),
            FakeDriver::default(),
            FakeHost::default(),
            &opentelemetry::global::meter("test"),
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while m.status().pools[0].ready < 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let api = Api(m);
        let request = ClaimSessionRequest {
            template_id: "web-v1".into(),
            labels: [("job".into(), "7".into()), ("team".into(), "a".into())].into(),
            idempotency_key: "job-7".into(),
            ..ClaimSessionRequest::default()
        };
        let claim =
            async |r: &ClaimSessionRequest| api.claim_session(Request::new(r.clone())).await.map(|r| r.into_inner().session.unwrap());
        let first = claim(&request).await.unwrap();
        assert_eq!(claim(&request).await.unwrap(), first);
        let mut changed = request.clone();
        changed.labels.insert("team".into(), "b".into());
        assert_eq!(claim(&changed).await.unwrap_err().code(), tonic::Code::FailedPrecondition);

        let by_key = GetSessionRequest { idempotency_key: "job-7".into(), ..GetSessionRequest::default() };
        assert_eq!(api.get_session(Request::new(by_key.clone())).await.unwrap().into_inner().session.unwrap(), first);
        let delete = DeleteSessionRequest { name: first.name.clone(), generation: first.generation };
        api.delete_session(Request::new(delete)).await.unwrap();
        let deleted = api.get_session(Request::new(by_key)).await.unwrap().into_inner().session.unwrap();
        assert_eq!((deleted.state(), deleted.name), (SessionState::Deleted, first.name));
        assert_eq!(claim(&request).await.unwrap_err().code(), tonic::Code::FailedPrecondition);
    }

    #[rstest]
    #[case::before_the_epoch(-1)]
    #[case::past_year_9999(i64::MAX)]
    #[tokio::test]
    async fn unstorable_expiries_are_refused(#[case] expires_at_ms: i64) {
        let dir = tempfile::tempdir().unwrap();
        let meter = opentelemetry::global::meter("test");
        let m = Manager::start(crate::testing::config(dir.path()), FakeDriver::default(), FakeHost::default(), &meter).await.unwrap();
        let api = Api(m);
        let req = SetSessionExpiryRequest { name: "roost-0".into(), generation: 1, expires_at_ms };
        let err = api.set_session_expiry(Request::new(req)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }
}
