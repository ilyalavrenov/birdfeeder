use std::{collections::BTreeMap, net::IpAddr, sync::LazyLock};

use regex::Regex;

use crate::v1::{ClaimSessionRequest, EgressPolicy, GetSessionRequest, ListSessionsRequest};

const MAX_IDLE_TIMEOUT_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const MAX_LABELS: usize = 32;
const MAX_LABEL_KEY_BYTES: usize = 128;
const MAX_LABEL_VALUE_BYTES: usize = 1024;
const MAX_EGRESS_ENTRIES: usize = 128;
const MAX_FQDN_BYTES: usize = 253;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
/// Last millisecond of year 9999. RFC 3339 can't go past that, so neither can roost's state files.
pub const MAX_EXPIRES_AT_MS: i64 = 253_402_300_799_999;

static TEMPLATE_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new("^[a-z0-9][a-z0-9_-]{0,63}$").expect("valid regex"));
static DNS_LABEL: LazyLock<Regex> = LazyLock::new(|| Regex::new("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$").expect("valid regex"));

/// Why we refused a request, worded for the caller.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    #[error("template_id must be a nonempty identifier of at most 64 characters")]
    TemplateId,
    #[error("idle_timeout_ms must be between zero and seven days")]
    IdleTimeout,
    #[error("idempotency_key must be at most {MAX_IDEMPOTENCY_KEY_BYTES} bytes")]
    IdempotencyKey,
    #[error("expires_at_ms must be zero for no expiry, or unix milliseconds before the year 10000")]
    Expiry,
    #[error("set exactly one of name and idempotency_key")]
    GetTarget,
    #[error("at most {MAX_LABELS} labels allowed")]
    TooManyLabels,
    #[error("label key or value exceeds limits")]
    LabelSize,
    #[error("at most {MAX_EGRESS_ENTRIES} entries per egress allowlist")]
    TooManyEgressEntries,
    #[error("invalid CIDR {0:?}")]
    Cidr(String),
    #[error("only IPv4 egress is supported")]
    Ipv6Egress,
    #[error("invalid FQDN")]
    Fqdn,
    #[error("invalid FQDN label")]
    FqdnLabel,
}

impl From<RequestError> for tonic::Status {
    fn from(err: RequestError) -> Self {
        Self::invalid_argument(err.to_string())
    }
}

/// Checks a claim against the limits servers enforce.
pub fn validate_claim(m: &ClaimSessionRequest) -> Result<(), RequestError> {
    if !TEMPLATE_ID.is_match(&m.template_id) {
        return Err(RequestError::TemplateId);
    }
    if !(0..=MAX_IDLE_TIMEOUT_MS).contains(&m.idle_timeout_ms) {
        return Err(RequestError::IdleTimeout);
    }
    if m.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(RequestError::IdempotencyKey);
    }
    validate_labels(&m.labels)?;
    m.egress.as_ref().map_or(Ok(()), validate_egress)
}

/// Checks a `SetSessionExpiryRequest.expires_at_ms` against the range servers can store.
pub fn validate_expiry(expires_at_ms: i64) -> Result<(), RequestError> {
    if !(0..=MAX_EXPIRES_AT_MS).contains(&expires_at_ms) {
        return Err(RequestError::Expiry);
    }
    Ok(())
}

/// Checks a `GetSessionRequest` names exactly one of: a session, or an idempotency key.
pub fn validate_get(m: &GetSessionRequest) -> Result<(), RequestError> {
    if m.name.is_empty() == m.idempotency_key.is_empty() {
        return Err(RequestError::GetTarget);
    }
    Ok(())
}

/// Checks a `ListSessionsRequest`'s label selector against the label limits.
pub fn validate_list(m: &ListSessionsRequest) -> Result<(), RequestError> {
    validate_labels(&m.labels)
}

fn validate_labels(labels: &BTreeMap<String, String>) -> Result<(), RequestError> {
    if labels.len() > MAX_LABELS {
        return Err(RequestError::TooManyLabels);
    }
    if labels.iter().any(|(k, v)| k.is_empty() || k.len() > MAX_LABEL_KEY_BYTES || v.len() > MAX_LABEL_VALUE_BYTES) {
        return Err(RequestError::LabelSize);
    }
    Ok(())
}

fn validate_egress(e: &EgressPolicy) -> Result<(), RequestError> {
    if e.cidr_allowlist.len() > MAX_EGRESS_ENTRIES || e.fqdn_allowlist.len() > MAX_EGRESS_ENTRIES {
        return Err(RequestError::TooManyEgressEntries);
    }
    e.cidr_allowlist.iter().try_for_each(|c| validate_cidr(c))?;
    e.fqdn_allowlist.iter().try_for_each(|d| validate_fqdn(d))
}

/// Takes a prefix like 10.0.0.0/8, or a bare address meaning just that one host.
fn validate_cidr(c: &str) -> Result<(), RequestError> {
    let (addr, bits) = match c.split_once('/') {
        Some((addr, bits)) => (addr, Some(bits)),
        None => (c, None),
    };
    let Ok(addr) = addr.parse::<IpAddr>() else {
        return Err(RequestError::Cidr(c.to_owned()));
    };
    let max_bits = if addr.is_ipv4() { 32 } else { 128 };
    // prefix length is plain decimal: no sign, no leading zeros.
    let bits_ok = bits.is_none_or(|b| {
        !b.is_empty()
            && b.bytes().all(|d| d.is_ascii_digit())
            && (b == "0" || !b.starts_with('0'))
            && b.parse::<u32>().is_ok_and(|n| n <= max_bits)
    });
    if !bits_ok {
        return Err(RequestError::Cidr(c.to_owned()));
    }
    if !addr.is_ipv4() {
        return Err(RequestError::Ipv6Egress);
    }
    Ok(())
}

fn validate_fqdn(domain: &str) -> Result<(), RequestError> {
    let domain = domain.strip_prefix("*.").unwrap_or(domain);
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    if domain.is_empty() || domain.len() > MAX_FQDN_BYTES {
        return Err(RequestError::Fqdn);
    }
    if !domain.split('.').all(|label| DNS_LABEL.is_match(&label.to_lowercase())) {
        return Err(RequestError::FqdnLabel);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn claim() -> ClaimSessionRequest {
        ClaimSessionRequest { template_id: "web-v1".into(), ..Default::default() }
    }

    fn claim_with(edit: impl FnOnce(&mut ClaimSessionRequest)) -> ClaimSessionRequest {
        let mut m = claim();
        edit(&mut m);
        m
    }

    fn egress(cidrs: &[&str], fqdns: &[&str]) -> EgressPolicy {
        EgressPolicy {
            cidr_allowlist: cidrs.iter().map(ToString::to_string).collect(),
            fqdn_allowlist: fqdns.iter().map(ToString::to_string).collect(),
            smtp_allowed: false,
        }
    }

    #[rstest]
    #[case::empty_template(claim_with(|m| m.template_id = String::new()), RequestError::TemplateId)]
    #[case::path_template(claim_with(|m| m.template_id = "../web".into()), RequestError::TemplateId)]
    #[case::idle_timeout_too_long(claim_with(|m| m.idle_timeout_ms = i64::MAX), RequestError::IdleTimeout)]
    #[case::negative_idle_timeout(claim_with(|m| m.idle_timeout_ms = -1), RequestError::IdleTimeout)]
    #[case::label_value_too_long(claim_with(|m| m.labels = BTreeMap::from([("key".into(), "x".repeat(1025))])), RequestError::LabelSize)]
    #[case::empty_label_key(claim_with(|m| m.labels = BTreeMap::from([(String::new(), "v".into())])), RequestError::LabelSize)]
    #[case::too_many_labels(claim_with(|m| m.labels = (0..33).map(|i| (i.to_string(), String::new())).collect()), RequestError::TooManyLabels)]
    #[case::too_many_cidrs(claim_with(|m| m.egress = Some(egress(&[""; 129], &[]))), RequestError::TooManyEgressEntries)]
    #[case::wildcard_without_dot(claim_with(|m| m.egress = Some(egress(&[], &["*example.com"]))), RequestError::FqdnLabel)]
    #[case::empty_fqdn_label(claim_with(|m| m.egress = Some(egress(&[], &["a..example.com"]))), RequestError::FqdnLabel)]
    #[case::ipv6(claim_with(|m| m.egress = Some(egress(&["::1"], &[]))), RequestError::Ipv6Egress)]
    #[case::prefix_too_long(claim_with(|m| m.egress = Some(egress(&["10.0.0.0/33"], &[]))), RequestError::Cidr("10.0.0.0/33".into()))]
    #[case::prefix_leading_zero(claim_with(|m| m.egress = Some(egress(&["10.0.0.0/08"], &[]))), RequestError::Cidr("10.0.0.0/08".into()))]
    #[case::empty_prefix(claim_with(|m| m.egress = Some(egress(&["10.0.0.0/"], &[]))), RequestError::Cidr("10.0.0.0/".into()))]
    #[case::idempotency_key_too_long(claim_with(|m| m.idempotency_key = "k".repeat(129)), RequestError::IdempotencyKey)]
    fn claims_past_a_limit_are_refused(#[case] m: ClaimSessionRequest, #[case] want: RequestError) {
        assert_eq!(validate_claim(&m), Err(want));
    }

    #[test]
    fn claims_at_every_limit_are_accepted() {
        let mut m = claim();
        m.egress = Some(egress(&["1.2.3.4", "10.0.0.0/8", "0.0.0.0/0"], &["*.example.com", "EXAMPLE.org."]));
        m.idle_timeout_ms = MAX_IDLE_TIMEOUT_MS;
        m.idempotency_key = "k".repeat(128);
        assert_eq!(validate_claim(&m), Ok(()));
    }

    #[rstest]
    #[case::neither("", "", Err(RequestError::GetTarget))]
    #[case::both("roost-0", "k", Err(RequestError::GetTarget))]
    #[case::name("roost-0", "", Ok(()))]
    #[case::idempotency_key("", "k", Ok(()))]
    fn gets_name_exactly_one_target(#[case] name: &str, #[case] key: &str, #[case] want: Result<(), RequestError>) {
        assert_eq!(validate_get(&GetSessionRequest { name: name.into(), idempotency_key: key.into() }), want);
    }

    #[rstest]
    #[case::negative(-1, Err(RequestError::Expiry))]
    #[case::min(i64::MIN, Err(RequestError::Expiry))]
    #[case::past_year_9999(MAX_EXPIRES_AT_MS + 1, Err(RequestError::Expiry))]
    #[case::max(i64::MAX, Err(RequestError::Expiry))]
    #[case::no_expiry(0, Ok(()))]
    #[case::epoch_plus_one(1, Ok(()))]
    #[case::end_of_year_9999(MAX_EXPIRES_AT_MS, Ok(()))]
    fn expiry_boundary_limits(#[case] expires_at_ms: i64, #[case] want: Result<(), RequestError>) {
        assert_eq!(validate_expiry(expires_at_ms), want);
    }
}
