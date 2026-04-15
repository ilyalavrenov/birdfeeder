//! Builds each container's OCI bundle config out of its image config plus the manifest.

use std::collections::BTreeMap;

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Deserializer, Serialize};

use guestapi::workload::Container;

/// The bundle's root dir. Has to match what convert and validate-bundle produce.
pub const ROOTFS: &str = "rootfs";
const OCI_VERSION: &str = "1.3.0";
const MAX_OPEN_FILES: u64 = 1024;
const MAX_PIDS: i64 = 256;
const CAPS: [&str; 8] =
    ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_NET_BIND_SERVICE"];

/// The bit of an image's config.json the guest actually uses: process defaults. Host paths, hooks,
/// namespaces, capabilities and device access from an input bundle don't get a say in the guest.
#[derive(Debug, Default, Deserialize)]
pub struct ImageSpec {
    #[serde(default)]
    pub process: Option<ImageProcess>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ImageProcess {
    #[serde(deserialize_with = "nullable")]
    pub args: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    pub env: Vec<String>,
    pub cwd: String,
    pub user: User,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub umask: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty", deserialize_with = "nullable")]
    pub additional_gids: Vec<u32>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub username: String,
}

/// Go-based OCI tools write an empty list as `null`.
fn nullable<'de, D: Deserializer<'de>, T: Default + Deserialize<'de>>(d: D) -> Result<T, D::Error> {
    Ok(Option::deserialize(d)?.unwrap_or_default())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Spec {
    pub oci_version: &'static str,
    pub process: Process,
    pub root: Root,
    pub hostname: String,
    pub mounts: Vec<Mount>,
    pub linux: Linux,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Process {
    pub user: User,
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
    pub cwd: String,
    pub capabilities: Capabilities,
    pub rlimits: Vec<Rlimit>,
    pub no_new_privileges: bool,
}

#[derive(Debug, Serialize)]
pub struct Capabilities {
    pub bounding: &'static [&'static str],
    pub effective: &'static [&'static str],
    pub permitted: &'static [&'static str],
}

#[derive(Debug, Serialize)]
pub struct Rlimit {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub hard: u64,
    pub soft: u64,
}

#[derive(Debug, Serialize)]
pub struct Root {
    pub path: &'static str,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Mount {
    pub destination: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub source: String,
    pub options: &'static [&'static str],
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Linux {
    pub resources: Resources,
    pub cgroups_path: String,
    pub namespaces: Vec<Namespace>,
    pub masked_paths: &'static [&'static str],
    pub readonly_paths: &'static [&'static str],
}

#[derive(Debug, Serialize)]
pub struct Resources {
    pub pids: Pids,
}

#[derive(Debug, Serialize)]
pub struct Pids {
    pub limit: i64,
}

#[derive(Debug, Serialize)]
pub struct Namespace {
    #[serde(rename = "type")]
    pub kind: &'static str,
}

fn mount(destination: &str, kind: &'static str, source: &str, options: &'static [&'static str]) -> Mount {
    Mount { destination: destination.into(), kind, source: source.into(), options }
}

pub fn bundle_spec(image: &ImageSpec, c: &Container, volumes: &str) -> Result<Spec> {
    let Some(base) = &image.process else { bail!("image bundle needs process defaults") };
    let args = if c.args.is_empty() { base.args.clone() } else { c.args.clone() };
    ensure!(!args.is_empty() && base.cwd.starts_with('/'), "image needs args and an absolute working directory");
    let mut env = BTreeMap::new();
    for e in &base.env {
        match e.split_once('=') {
            Some((k, v)) if !k.is_empty() => env.insert(k, v),
            _ => bail!("invalid image environment entry"),
        };
    }
    env.extend(c.env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    let env: Vec<String> = env.into_iter().map(|(k, v)| format!("{k}={v}")).collect();
    ensure!(args.iter().chain(&env).all(|v| !v.contains('\0')), "NUL in image process defaults");

    let mut mounts = vec![
        mount("/proc", "proc", "proc", &["nosuid", "noexec", "nodev"]),
        mount("/dev", "tmpfs", "tmpfs", &["nosuid", "strictatime", "mode=755", "size=16m"]),
        mount("/dev/pts", "devpts", "devpts", &["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620", "gid=5"]),
        mount("/dev/shm", "tmpfs", "shm", &["nosuid", "nodev", "noexec", "mode=1777", "size=16m"]),
        mount("/sys", "sysfs", "sysfs", &["nosuid", "noexec", "nodev", "ro"]),
    ];
    for file in ["/etc/resolv.conf", "/etc/hosts"] {
        mounts.push(mount(file, "bind", file, &["bind", "ro", "nosuid", "nodev", "noexec"]));
    }
    for (volume, destination) in &c.mounts {
        mounts.push(mount(destination, "bind", &format!("{volumes}/{volume}"), &["rbind", "nosuid", "nodev"]));
    }
    Ok(Spec {
        oci_version: OCI_VERSION,
        process: Process {
            user: base.user.clone(),
            args,
            env,
            cwd: base.cwd.clone(),
            capabilities: Capabilities { bounding: &CAPS, effective: &CAPS, permitted: &CAPS },
            rlimits: vec![Rlimit { kind: "RLIMIT_NOFILE", hard: MAX_OPEN_FILES, soft: MAX_OPEN_FILES }],
            no_new_privileges: true,
        },
        root: Root { path: ROOTFS },
        hostname: c.name.to_string(),
        mounts,
        linux: Linux {
            resources: Resources { pids: Pids { limit: MAX_PIDS } },
            cgroups_path: format!("/birdfeeder/{}", c.name),
            namespaces: ["pid", "mount", "ipc", "uts", "cgroup"].map(|kind| Namespace { kind }).into(),
            masked_paths: &["/proc/kcore", "/proc/keys", "/proc/timer_list", "/proc/sched_debug", "/sys/firmware"],
            readonly_paths: &["/proc/asound", "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"],
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(json: &str) -> ImageSpec {
        serde_json::from_str(json).unwrap()
    }

    fn web() -> Container {
        Container::new("web".parse().unwrap(), "app".parse().unwrap())
    }

    #[test]
    fn keeps_process_defaults_and_drops_image_policy() {
        let image = image(
            r#"{"process":{"args":["/bin/old"],"cwd":"/app","env":["B=old","A=baked"],"user":{"uid":1000,"gid":1000}},
                "mounts":[{"destination":"/host","source":"/host-secret"}],"hooks":{},
                "linux":{"namespaces":[{"type":"network","path":"/host/netns"}]}}"#,
        );
        let c = Container {
            args: vec!["/bin/new".into()],
            env: [("B".into(), "override".into()), ("C".into(), "extra".into())].into(),
            mounts: [("data".parse().unwrap(), "/data".into())].into(),
            ..web()
        };
        let s = bundle_spec(&image, &c, "/volumes").unwrap();
        assert_eq!(s.process.args, ["/bin/new"]);
        assert_eq!(s.process.env, ["A=baked", "B=override", "C=extra"]);
        assert_eq!(s.process.user, User { uid: 1000, gid: 1000, ..User::default() });
        assert!(s.process.no_new_privileges);
        assert_eq!(s.linux.cgroups_path, "/birdfeeder/web");
        assert!(s.mounts.iter().all(|m| m.source != "/host-secret"));
        assert_eq!(s.mounts.last().unwrap(), &mount("/data", "bind", "/volumes/data", &["rbind", "nosuid", "nodev"]));
        let json = serde_json::to_value(&s).unwrap();
        assert!(json.get("hooks").is_none());
        assert!(json["linux"]["namespaces"].as_array().unwrap().iter().all(|n| n["type"] != "network" && n.get("path").is_none()));
        assert_eq!(json["linux"]["resources"]["pids"]["limit"], 256);
    }

    #[test]
    fn requires_a_usable_process() {
        for json in [
            "{}",
            r#"{"process":{}}"#,
            r#"{"process":{"args":["sh"],"cwd":"relative"}}"#,
            r#"{"process":{"args":["bad\u0000arg"],"cwd":"/"}}"#,
            r#"{"process":{"args":["sh"],"cwd":"/","env":["=x"]}}"#,
        ] {
            assert!(bundle_spec(&image(json), &web(), "/volumes").is_err(), "{json}");
        }
        let c = Container { args: vec!["/app".into()], ..web() };
        let s = bundle_spec(&image(r#"{"process":{"cwd":"/","args":null,"env":null}}"#), &c, "/volumes").unwrap();
        assert_eq!(s.process.args, ["/app"], "container args supply the command for an image without one");
        assert!(serde_json::to_value(&s).unwrap()["process"].get("env").is_none());
    }
}
