//! The workload contract. roost publishes a template's [`Metadata`] through MMDS, and the guest checks it again
//! before acting on it. Decoding checks each field. [`Metadata::validate`] and [`Manifest::validate`] check the
//! rules that span fields.

use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fmt;
use std::num::NonZeroU16;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Max containers, volumes, readiness probes or blobs a workload can have.
pub const MAX_ITEMS: usize = 16;
const MAX_MANIFEST_BYTES: usize = 32 << 10;
const MAX_EXEC_ITEMS: usize = 128;

/// `blobs` is in block device attach order, starting at /dev/vdc after the root and scratch disks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metadata {
    pub version: u32,
    pub template_id: Identifier,
    pub blobs: Vec<Identifier>,
    pub manifest: Manifest,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub containers: Vec<Container>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<Identifier>,
    pub readiness: Vec<Probe>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Container {
    pub name: Identifier,
    pub blob: Identifier,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Volume name to the path it's mounted at.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub mounts: BTreeMap<Identifier, String>,
}

impl Container {
    /// A container with no arguments, environment or mounts.
    #[must_use]
    pub fn new(name: Identifier, blob: Identifier) -> Self {
        Self { name, blob, args: Vec::new(), env: BTreeMap::new(), mounts: BTreeMap::new() }
    }
}

/// A port the guest's workload listens on once it's ready. On the wire it's `name` plus exactly one of `tcp_port`
/// or `vsock_port`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "WireProbe", into = "WireProbe")]
pub struct Probe {
    pub name: Identifier,
    pub target: ProbeTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeTarget {
    Tcp(NonZeroU16),
    Vsock(NonZeroU16),
}

#[derive(Serialize, Deserialize)]
struct WireProbe {
    name: Identifier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tcp_port: Option<NonZeroU16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vsock_port: Option<NonZeroU16>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("readiness probe {name} needs exactly one of tcp_port and vsock_port")]
pub struct ProbeTransportError {
    name: Identifier,
}

impl TryFrom<WireProbe> for Probe {
    type Error = ProbeTransportError;

    fn try_from(w: WireProbe) -> Result<Self, Self::Error> {
        let target = match (w.tcp_port, w.vsock_port) {
            (Some(port), None) => ProbeTarget::Tcp(port),
            (None, Some(port)) => ProbeTarget::Vsock(port),
            _ => return Err(ProbeTransportError { name: w.name }),
        };
        Ok(Self { name: w.name, target })
    }
}

impl From<Probe> for WireProbe {
    fn from(p: Probe) -> Self {
        let (tcp_port, vsock_port) = match p.target {
            ProbeTarget::Tcp(port) => (Some(port), None),
            ProbeTarget::Vsock(port) => (None, Some(port)),
        };
        Self { name: p.name, tcp_port, vsock_port }
    }
}

/// A short lowercase name, used for templates, containers, blobs, volumes and probes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Identifier(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not an identifier: up to 64 lowercase letters, digits, '_' and '-', starting with a letter or digit")]
pub struct InvalidIdentifier(String);

impl Identifier {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Identifier {
    type Error = InvalidIdentifier;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if is_identifier(&s) { Ok(Self(s)) } else { Err(InvalidIdentifier(s)) }
    }
}

impl FromStr for Identifier {
    type Err = InvalidIdentifier;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_owned().try_into()
    }
}

impl From<Identifier> for String {
    fn from(id: Identifier) -> Self {
        id.0
    }
}

impl AsRef<str> for Identifier {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// An identifier is always a single path component. No `/`, and it can't be `.` or `..`.
impl AsRef<Path> for Identifier {
    fn as_ref(&self) -> &Path {
        Path::new(&self.0)
    }
}

impl AsRef<OsStr> for Identifier {
    fn as_ref(&self) -> &OsStr {
        OsStr::new(&self.0)
    }
}

/// Fine because an identifier sorts and hashes the same as its string.
impl Borrow<str> for Identifier {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for Identifier {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Identifier {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

#[must_use]
pub fn is_identifier(s: &str) -> bool {
    let valid = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    matches!(s.as_bytes().first(), Some(&c) if valid(c)) && s.len() <= 64 && s.bytes().all(|c| valid(c) || c == b'_' || c == b'-')
}

/// What makes a workload invalid beyond checking each field on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WorkloadError {
    #[error("invalid guest metadata version or blob count")]
    Metadata,
    #[error("duplicate blob")]
    DuplicateBlob,
    #[error("blobs must follow sorted attachment order")]
    UnsortedBlobs,
    #[error("container references missing blob")]
    MissingBlob,
    #[error("manifest exceeds 32 KiB")]
    ManifestTooLarge,
    #[error("manifest needs 1..16 containers and readiness probes, and at most 16 volumes")]
    ItemCount,
    #[error("duplicate volume")]
    DuplicateVolume,
    #[error("duplicate container name")]
    DuplicateContainer,
    #[error("container configuration exceeds limits")]
    ContainerLimits,
    #[error("invalid volume mount")]
    InvalidMount,
    #[error("duplicate readiness probe")]
    DuplicateProbe,
    #[error("invalid environment entry")]
    InvalidEnv,
    #[error("invalid command argument")]
    InvalidArg,
}

impl Metadata {
    pub fn validate(&self) -> Result<(), WorkloadError> {
        check(self.version == 1 && (1..=MAX_ITEMS).contains(&self.blobs.len()), WorkloadError::Metadata)?;
        let mut seen = BTreeSet::new();
        check(self.blobs.iter().all(|b| seen.insert(b)), WorkloadError::DuplicateBlob)?;
        check(self.blobs.is_sorted(), WorkloadError::UnsortedBlobs)?;
        check(self.manifest.containers.iter().all(|c| seen.contains(&c.blob)), WorkloadError::MissingBlob)?;
        self.manifest.validate()
    }
}

impl Manifest {
    pub fn validate(&self) -> Result<(), WorkloadError> {
        let size = serde_json::to_vec(self).expect("strings, integers and string-keyed maps always serialize").len();
        check(size <= MAX_MANIFEST_BYTES, WorkloadError::ManifestTooLarge)?;
        check(
            (1..=MAX_ITEMS).contains(&self.containers.len())
                && self.volumes.len() <= MAX_ITEMS
                && (1..=MAX_ITEMS).contains(&self.readiness.len()),
            WorkloadError::ItemCount,
        )?;
        let mut volumes = BTreeSet::new();
        check(self.volumes.iter().all(|v| volumes.insert(v)), WorkloadError::DuplicateVolume)?;
        let mut names = BTreeSet::new();
        for c in &self.containers {
            check(names.insert(&c.name), WorkloadError::DuplicateContainer)?;
            check(
                c.args.len() <= MAX_EXEC_ITEMS && c.env.len() <= MAX_EXEC_ITEMS && c.mounts.len() <= MAX_ITEMS,
                WorkloadError::ContainerLimits,
            )?;
            let mut destinations = BTreeSet::new();
            for (v, p) in &c.mounts {
                check(volumes.contains(v) && is_mount_path(p) && destinations.insert(p.as_str()), WorkloadError::InvalidMount)?;
            }
        }
        let mut probes = BTreeSet::new();
        check(self.readiness.iter().all(|p| probes.insert(&p.name)), WorkloadError::DuplicateProbe)?;
        for c in &self.containers {
            for (k, v) in &c.env {
                check(!k.is_empty() && !k.contains(['=', '\0']) && !v.contains('\0'), WorkloadError::InvalidEnv)?;
            }
            check(c.args.iter().all(|a| !a.contains('\0')), WorkloadError::InvalidArg)?;
        }
        Ok(())
    }
}

fn check(ok: bool, err: WorkloadError) -> Result<(), WorkloadError> {
    if ok { Ok(()) } else { Err(err) }
}

/// An absolute path that isn't `/` and is already clean: no `.`, `..` or empty components.
fn is_mount_path(p: &str) -> bool {
    p.strip_prefix('/').is_some_and(|rest| rest.split('/').all(|c| !c.is_empty() && c != "." && c != "..")) && !p.contains('\0')
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::{Value, json};

    use super::*;

    fn id(s: &str) -> Identifier {
        s.parse().unwrap()
    }

    fn web() -> Manifest {
        Manifest {
            containers: vec![Container::new(id("web"), id("a"))],
            readiness: vec![Probe { name: id("http"), target: ProbeTarget::Tcp(NonZeroU16::new(8080).unwrap()) }],
            ..Manifest::default()
        }
    }

    #[test]
    fn metadata_checks_blobs() {
        let mut md = Metadata { version: 1, template_id: id("v1"), blobs: vec![id("z"), id("a")], manifest: web() };
        assert_eq!(md.validate(), Err(WorkloadError::UnsortedBlobs));
        md.blobs = vec![id("z")];
        assert_eq!(md.validate(), Err(WorkloadError::MissingBlob));
        md.blobs = vec![id("a"), id("z")];
        md.validate().unwrap();
        md.version = 2;
        assert_eq!(md.validate(), Err(WorkloadError::Metadata));
    }

    fn shared_volume() -> Manifest {
        let mount = |path: &str| [(id("data"), path.to_owned())].into();
        Manifest {
            volumes: vec![id("data")],
            containers: vec![
                Container { mounts: mount("/output"), ..Container::new(id("writer"), id("worker")) },
                Container { mounts: mount("/www"), ..Container::new(id("web"), id("server")) },
            ],
            ..web()
        }
    }

    #[test]
    fn containers_share_a_volume() {
        shared_volume().validate().unwrap();
    }

    #[rstest]
    #[case::unknown_volume("missing", "/tmp")]
    #[case::root("data", "/")]
    #[case::trailing_slash("data", "/www/")]
    #[case::dot_dot("data", "/a/../b")]
    #[case::relative("data", "rel")]
    #[case::nul("data", "/bad\0path")]
    fn rejects_invalid_mounts(#[case] volume: &str, #[case] path: &str) {
        let mut m = shared_volume();
        m.containers[1].mounts = [(id(volume), path.into())].into();
        assert_eq!(m.validate(), Err(WorkloadError::InvalidMount));
    }

    #[test]
    fn rejects_a_duplicate_mount_destination() {
        let mut m = shared_volume();
        m.volumes.push(id("second"));
        m.containers[0].mounts.insert(id("second"), "/output".into());
        assert_eq!(m.validate(), Err(WorkloadError::InvalidMount));
    }

    #[rstest]
    #[case::no_transport(json!({"name": "http"}))]
    #[case::zero_port(json!({"name": "http", "tcp_port": 0}))]
    #[case::both_transports(json!({"name": "http", "tcp_port": 8080, "vsock_port": 5000}))]
    fn probe_needs_one_transport(#[case] bad: Value) {
        assert!(serde_json::from_value::<Probe>(bad).is_err());
    }

    #[rstest]
    #[case::tcp(json!({"name": "http", "tcp_port": 8080}), ProbeTarget::Tcp(NonZeroU16::new(8080).unwrap()))]
    #[case::vsock(json!({"name": "agent", "vsock_port": 5000}), ProbeTarget::Vsock(NonZeroU16::new(5000).unwrap()))]
    fn probe_wire_form_round_trips(#[case] wire: Value, #[case] target: ProbeTarget) {
        let probe: Probe = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(probe.target, target);
        assert_eq!(serde_json::to_value(&probe).unwrap(), wire);
    }

    #[rstest]
    #[case::lowercase("web", true)]
    #[case::digit_first_with_separators("0-a_b", true)]
    #[case::longest(&"a".repeat(64), true)]
    #[case::separator_first("-web", false)]
    #[case::uppercase("Web", false)]
    #[case::empty("", false)]
    #[case::too_long(&"a".repeat(65), false)]
    fn identifiers(#[case] name: &str, #[case] ok: bool) {
        assert_eq!(name.parse::<Identifier>().is_ok(), ok);
        assert_eq!(serde_json::from_value::<Identifier>(json!(name)).is_ok(), ok);
    }

    #[test]
    fn rejects_unsafe_exec_strings() {
        let mut m = web();
        m.containers[0].env.insert("A=B".into(), "x".into());
        assert_eq!(m.validate(), Err(WorkloadError::InvalidEnv));
        let mut m = web();
        m.containers[0].args.push("a\0b".into());
        assert_eq!(m.validate(), Err(WorkloadError::InvalidArg));
    }
}
