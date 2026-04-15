//! The bundle's config.json: the subset of an OCI runtime spec the guest reads.

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Deserializer, Serialize};

/// Docker supplies this PATH when an image sets none; images built for Docker rely on it.
pub const DEFAULT_PATH: &str = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const OCI_VERSION: &str = "1.3.0";

/// An image's process defaults, from its config blob.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ImageConfig {
    #[serde(default, deserialize_with = "nullable")]
    pub user: String,
    #[serde(default, deserialize_with = "nullable")]
    pub env: Vec<String>,
    #[serde(default, deserialize_with = "nullable")]
    pub entrypoint: Vec<String>,
    #[serde(default, deserialize_with = "nullable")]
    pub cmd: Vec<String>,
    #[serde(default, deserialize_with = "nullable")]
    pub working_dir: String,
}

/// The image config blob; only its process defaults matter here.
#[derive(Debug, Default, Deserialize)]
pub struct ConfigFile {
    #[serde(default, deserialize_with = "nullable")]
    pub config: ImageConfig,
}

fn nullable<'de, D: Deserializer<'de>, T: Default + Deserialize<'de>>(d: D) -> Result<T, D::Error> {
    Ok(Option::deserialize(d)?.unwrap_or_default())
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Spec {
    #[serde(rename = "ociVersion")]
    version: &'static str,
    pub process: Process,
    root: Root,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Process {
    pub user: User,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    pub cwd: String,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    #[serde(rename = "additionalGids", skip_serializing_if = "Vec::is_empty")]
    pub additional_gids: Vec<u32>,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct Root {
    path: &'static str,
}

/// Maps an image's process defaults onto the bundle config. passwd and group are the image's own files, or empty
/// if it has none. Args can be empty for base images like distroless. A template's container args fill them in,
/// and the guest rejects a container that still has none.
pub fn image_spec(cfg: &ImageConfig, passwd: &[u8], group: &[u8]) -> Result<Spec> {
    let args = cfg.entrypoint.iter().chain(&cfg.cmd).cloned().collect();
    let mut env = cfg.env.clone();
    if !env.iter().any(|e| e.starts_with("PATH=")) {
        env.push(DEFAULT_PATH.into());
    }
    let cwd = if cfg.working_dir.is_empty() { "/".into() } else { cfg.working_dir.clone() };
    Ok(Spec {
        version: OCI_VERSION,
        process: Process { user: resolve_user(&cfg.user, passwd, group)?, args, env, cwd },
        root: Root { path: "rootfs" },
    })
}

/// Encodes spec compactly, as config.json.
pub fn encode(spec: &Spec) -> Vec<u8> {
    serde_json::to_vec(spec).expect("a spec always encodes")
}

struct PasswdEntry<'a> {
    name: &'a str,
    uid: u32,
    gid: u32,
}

struct GroupEntry<'a> {
    name: &'a str,
    gid: u32,
    members: Vec<&'a str>,
}

/// Follows Docker's USER rules: user[:group], each a name or numeric ID, with the primary group from passwd and
/// supplementary groups from group when the user has an entry.
pub fn resolve_user(spec: &str, passwd: &[u8], group: &[u8]) -> Result<User> {
    let spec = if spec.is_empty() { "0" } else { spec };
    let (user_part, group_part) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let users = parse_passwd(passwd).context("parse /etc/passwd")?;
    let groups = parse_group(group).context("parse /etc/group")?;
    let mut out = User::default();
    let named = lookup(&users, user_part, |e| (e.name, e.uid));
    if let Some(u) = named {
        (out.uid, out.gid) = (u.uid, u.gid);
    } else {
        out.uid = numeric_id(user_part).with_context(|| format!("user {user_part:?} isn't in the image's /etc/passwd"))?;
    }
    if let Some(group_part) = group_part {
        out.gid = match lookup(&groups, group_part, |e| (e.name, e.gid)) {
            Some(g) => g.gid,
            None => numeric_id(group_part).with_context(|| format!("group {group_part:?} isn't in the image's /etc/group"))?,
        };
    }
    let Some(u) = named else { return Ok(out) };
    for g in &groups {
        if g.gid != out.gid && g.members.contains(&u.name) && !out.additional_gids.contains(&g.gid) {
            out.additional_gids.push(g.gid);
        }
    }
    Ok(out)
}

fn parse_passwd(data: &[u8]) -> Result<Vec<PasswdEntry<'_>>> {
    split_db(data, 7)?.into_iter().map(|f| Ok(PasswdEntry { name: f[0], uid: numeric_id(f[2])?, gid: numeric_id(f[3])? })).collect()
}

fn parse_group(data: &[u8]) -> Result<Vec<GroupEntry<'_>>> {
    split_db(data, 4)?
        .into_iter()
        .map(|f| {
            let members = if f[3].is_empty() { Vec::new() } else { f[3].split(',').collect() };
            Ok(GroupEntry { name: f[0], gid: numeric_id(f[2])?, members })
        })
        .collect()
}

fn split_db(data: &[u8], fields: usize) -> Result<Vec<Vec<&str>>> {
    let text = std::str::from_utf8(data).context("not UTF-8")?;
    let mut out = Vec::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < fields {
            bail!("short line {line:?}");
        }
        out.push(f);
    }
    Ok(out)
}

/// Matches a name first, then a numeric ID, so USER 1000 still picks up that user's groups.
fn lookup<'e, T>(db: &'e [T], key: &str, ident: impl Fn(&T) -> (&str, u32)) -> Option<&'e T> {
    db.iter().find(|e| ident(e).0 == key).or_else(|| {
        let id = numeric_id(key).ok()?;
        db.iter().find(|e| ident(e).1 == id)
    })
}

fn numeric_id(s: &str) -> Result<u32> {
    // u32's parser would also take a leading +.
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        bail!("invalid ID {s:?}");
    }
    s.parse().with_context(|| format!("invalid ID {s:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD: &str = "root:x:0:0:root:/root:/bin/sh\n# comment\n\napp:x:1000:1001::/home/app:/bin/sh\n";
    const GROUP: &str = "root:x:0:\napp:x:1001:\nwheel:x:10:root,app\naudio:x:29:app\nstaff:x:50:\n";

    fn user(uid: u32, gid: u32, additional_gids: &[u32]) -> User {
        User { uid, gid, additional_gids: additional_gids.to_vec() }
    }

    #[test]
    fn resolves_users_like_docker() {
        for (spec, want) in [
            ("", user(0, 0, &[10])),
            ("app", user(1000, 1001, &[10, 29])),
            ("1000", user(1000, 1001, &[10, 29])),
            ("app:staff", user(1000, 50, &[10, 29])),
            ("app:10", user(1000, 10, &[29])),
            ("4242", user(4242, 0, &[])),
            ("4242:4343", user(4242, 4343, &[])),
        ] {
            assert_eq!(resolve_user(spec, PASSWD.as_bytes(), GROUP.as_bytes()).unwrap(), want, "{spec}");
        }
        for spec in ["nobody", "app:nogroup", "-1", "+1", "99999999999"] {
            assert!(resolve_user(spec, PASSWD.as_bytes(), GROUP.as_bytes()).is_err(), "{spec}");
        }
        assert_eq!(resolve_user("1000:1000", b"", b"").unwrap(), user(1000, 1000, &[]), "numeric IDs need no account files");
        assert!(resolve_user("app", b"app:x:notanumber:0::/:/bin/sh\n", b"").is_err());
        assert!(resolve_user("app", b"app:x:1000\n", b"").is_err());
    }

    #[test]
    fn image_spec_defaults() {
        let cfg = ImageConfig {
            entrypoint: vec!["/bin/server".into()],
            cmd: vec!["-port".into(), "80".into()],
            env: vec!["A=1".into()],
            ..Default::default()
        };
        let s = image_spec(&cfg, b"", b"").unwrap();
        assert_eq!(s.process.args, ["/bin/server", "-port", "80"]);
        assert_eq!(s.process.env, ["A=1", DEFAULT_PATH], "Docker's default PATH applies when the image sets none");
        assert_eq!(s.process.cwd, "/");

        let cfg =
            ImageConfig { cmd: vec!["python".into()], env: vec!["PATH=/opt/bin".into()], working_dir: "/app".into(), ..Default::default() };
        let s = image_spec(&cfg, b"", b"").unwrap();
        assert_eq!(s.process.env, ["PATH=/opt/bin"]);
        assert_eq!(s.process.cwd, "/app");

        let s = image_spec(&ImageConfig { env: vec!["A=1".into()], ..Default::default() }, b"", b"").unwrap();
        assert!(s.process.args.is_empty(), "a template's container args can supply the command");
    }

    #[test]
    fn encodes_the_spec_subset() {
        let cfg = ImageConfig { cmd: vec!["x".into()], user: "app".into(), ..Default::default() };
        let spec = image_spec(&cfg, PASSWD.as_bytes(), GROUP.as_bytes()).unwrap();
        assert_eq!(
            String::from_utf8(encode(&spec)).unwrap(),
            r#"{"ociVersion":"1.3.0","process":{"user":{"uid":1000,"gid":1001,"additionalGids":[10,29]},"args":["x"],"env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"cwd":"/"},"root":{"path":"rootfs"}}"#
        );
    }

    #[test]
    fn config_file_tolerates_nulls() {
        let cfg: ConfigFile = serde_json::from_str(r#"{"config":{"Cmd":null,"Env":["A=1"],"User":null}}"#).unwrap();
        assert_eq!(cfg.config, ImageConfig { env: vec!["A=1".into()], ..Default::default() });
        let cfg: ConfigFile = serde_json::from_str(r#"{"config":null}"#).unwrap();
        assert_eq!(cfg.config, ImageConfig::default());
    }
}
