use std::fs;
use std::os::unix::fs::symlink;

use rstest::rstest;
use serde_json::{Value, json};

use super::*;
use crate::testing::{EMPTY_SHA256, config_json};

fn parse(v: &Value) -> Result<Config> {
    Ok(serde_json::from_value(v.clone())?)
}

fn set(v: &mut Value, pointer: &str, value: Value) {
    let (parent, key) = pointer.rsplit_once('/').unwrap();
    v.pointer_mut(parent).unwrap().as_object_mut().unwrap().insert(key.to_owned(), value);
}

#[test]
fn defaults_and_disabled_limits() {
    let dirs = tempfile::tempdir().unwrap();
    let mut v = config_json(dirs.path());
    v["templates"][0]["conn_limit"] = json!(-1);
    v["templates"][0]["net_bytes_per_sec"] = json!(-1);
    v["console_max_bytes"] = json!(-1);
    v["max_unregistered_sec"] = json!(-5);
    let cfg = parse(&v).unwrap();
    let t = &cfg.templates[0];
    assert_eq!((t.conn_limit, t.net_bytes_per_sec, t.disk_ops_per_sec), (None, None, None));
    assert_eq!((cfg.console_max_bytes, cfg.max_unregistered), (None, None));
    assert_eq!(cfg.session_state_dir(), cfg.state_dir);
    assert_eq!(cfg.uffd_handler_bin(), PathBuf::from("/bin/uffd-handler"));
    let jailer = cfg.driver().jailer.unwrap();
    assert_eq!((jailer.bin, jailer.chroot_base), ("/bin/jailer".into(), cfg.state_dir.join("nest")));
}

#[rstest]
#[case::empty(json!({}), true)]
#[case::configured(json!({"uid_base": 20000, "cgroup_limits": true}), true)]
#[case::disabled(json!({"disabled": true}), false)]
#[case::disabled_with_settings(json!({"disabled": true, "uid_base": 20000}), false)]
fn jailer_on_unless_disabled(#[case] jailer: Value, #[case] on: bool) {
    let dirs = tempfile::tempdir().unwrap();
    let mut v = config_json(dirs.path());
    v["jailer"] = jailer;
    let cfg = parse(&v).unwrap();
    assert_eq!((cfg.driver().jailer.is_some(), cfg.chroot_base().is_some()), (on, on));
}

#[rstest]
#[case::zero_rate("/templates/0/disk_bytes_per_sec", json!(0))]
#[case::negative_rate("/templates/0/conn_limit", json!(-2))]
#[case::unknown_field("/surprise", json!(1))]
#[case::unknown_jailer_field("/jailer", json!({"chroot": "/x"}))]
#[case::unknown_snapshot_mode("/templates/0/snapshot", json!("always"))]
#[case::subnet_overlapping_the_guest_network("/subnet", json!("172.16.0.0/24"))]
#[case::uncanonical_subnet("/subnet", json!("172.20.0.1/24"))]
#[case::too_few_sessions_for_the_boots("/max_concurrent_boots", json!(3))]
#[case::ports_past_65535("/dnat_port_start", json!(65530))]
#[case::inverted_ttls("/fqdn_max_ttl_sec", json!(1))]
#[case::zero_pool_lifetime("/max_unregistered_sec", json!(0))]
#[case::zero_ready_timeout("/ready_timeout_sec", json!(0))]
#[case::ready_timeout_over_an_hour("/ready_timeout_sec", json!(3601))]
#[case::zero_reap_interval("/reap_interval_sec", json!(0))]
#[case::negative_interval("/metrics_interval_sec", json!(-1))]
#[case::short_kernel_digest("/kernel_sha256", json!("abc"))]
#[case::uppercase_digest("/templates/0/base_disk_sha256", json!(EMPTY_SHA256.to_uppercase()))]
#[case::pools_over_budget("/templates/0/pool_target", json!(3))]
#[case::bad_template_id("/templates/0/template_id", json!("Web"))]
#[case::relative_base_disk("/templates/0/base_disk", json!("base.ext4"))]
#[case::bad_endpoint_port("/templates/0/endpoints/http", json!(0))]
#[case::missing_blob_digest("/templates/0/blob_sha256", json!({}))]
fn invalid_configs_are_refused(#[case] pointer: &str, #[case] value: Value) {
    let dirs = tempfile::tempdir().unwrap();
    let mut v = config_json(dirs.path());
    parse(&v).unwrap();
    set(&mut v, pointer, value);
    assert!(parse(&v).is_err());
}

#[test]
fn duplicate_templates_are_refused() {
    let dirs = tempfile::tempdir().unwrap();
    let mut v = config_json(dirs.path());
    let template = v["templates"][0].clone();
    v["templates"].as_array_mut().unwrap().push(template);
    assert!(format!("{:#}", parse(&v).unwrap_err()).contains("duplicate template"));
}

#[test]
fn warmup_needs_lazy_snapshot_and_endpoint() {
    let dirs = tempfile::tempdir().unwrap();
    let mut v = config_json(dirs.path());
    v["templates"][0]["snapshot_warmup"] = json!([{"endpoint": "http", "path": "/"}]);
    assert!(format!("{:#}", parse(&v).unwrap_err()).contains(r#"needs snapshot "lazy""#));
    v["templates"][0]["snapshot"] = json!("lazy");
    parse(&v).unwrap();
    v["templates"][0]["snapshot_warmup"][0]["endpoint"] = json!("admin");
    assert!(format!("{:#}", parse(&v).unwrap_err()).contains("known endpoint"));
}

#[rstest]
#[case::run_contains_state("/state_dir", |d: &Path| json!(d.join("run/state")))]
#[case::run_is_state("/run_dir", |d: &Path| json!(d.join("state")))]
#[case::run_contains_sessions("/run_dir", |d: &Path| json!(d.join("state/sessions")))]
#[case::session_records_in_run("/session_state_dir", |d: &Path| json!(d.join("run/records")))]
#[case::relative_session_records("/session_state_dir", |_: &Path| json!("records"))]
#[case::run_contains_nest("/jailer/chroot_base", |d: &Path| json!(d.join("run/nest")))]
#[case::nest_contains_run("/run_dir", |d: &Path| json!(d.join("state/nest/firecracker/run")))]
#[case::unclean_run("/run_dir", |_: &Path| json!("/tmp/.."))]
#[case::kernel_in_run("/kernel_image_path", |d: &Path| json!(d.join("run/kernel")))]
#[case::binary_in_run("/firecracker_bin", |d: &Path| json!(d.join("run/bin/firecracker")))]
#[case::base_in_disks("/templates/0/base_disk", |d: &Path| json!(d.join("state/disks/base.ext4")))]
#[case::blob_in_nest("/templates/0/blobs/web", |d: &Path| json!(d.join("state/nest/firecracker/web.squashfs")))]
fn managed_dirs_must_not_overlap(#[case] pointer: &str, #[case] value: fn(&Path) -> Value) {
    let dirs = tempfile::tempdir().unwrap();
    let mut v = config_json(dirs.path());
    v["jailer"] = json!({});
    set(&mut v, pointer, value(dirs.path()));
    assert!(parse(&v).is_err());
}

#[test]
fn managed_dirs_may_nest_apart() {
    let dirs = tempfile::tempdir().unwrap();
    let mut v = config_json(dirs.path());
    let state = dirs.path().join("state");
    v["run_dir"] = json!(state.join("run"));
    v["templates"][0]["base_disk"] = json!(state.join("artifacts/base.ext4"));
    parse(&v).unwrap();
}

#[rstest]
#[case::state_alias(|d: &Path| d.join("state"), "/run_dir", |a: &Path| json!(a))]
#[case::artifact_alias(|d: &Path| d.join("run"), "/kernel_image_path", |a: &Path| json!(a.join("kernel")))]
#[case::missing_ancestor(|d: &Path| d.join("state"), "/run_dir", |a: &Path| json!(a.join("disks/nested")))]
#[case::root_alias(|_: &Path| PathBuf::from("/"), "/state_dir", |a: &Path| json!(a))]
fn managed_dirs_resolve_symlinks(#[case] target: fn(&Path) -> PathBuf, #[case] pointer: &str, #[case] value: fn(&Path) -> Value) {
    let dirs = tempfile::tempdir().unwrap();
    let mut v = config_json(dirs.path());
    fs::create_dir_all(dirs.path().join("state")).unwrap();
    fs::create_dir_all(dirs.path().join("run")).unwrap();
    let alias = dirs.path().join("alias");
    symlink(target(dirs.path()), &alias).unwrap();
    set(&mut v, pointer, value(&alias));
    assert!(parse(&v).is_err());
}

#[test]
fn symlinked_sessions_dir_is_resolved() {
    let dirs = tempfile::tempdir().unwrap();
    let v = config_json(dirs.path());
    let (state, run) = (dirs.path().join("state"), dirs.path().join("run"));
    fs::create_dir_all(&state).unwrap();
    fs::create_dir_all(&run).unwrap();
    symlink(&run, state.join("sessions")).unwrap();
    assert!(parse(&v).is_err());
}

#[test]
fn fingerprints_cover_what_shapes_guests() {
    let digest = |c: char| Sha256Hex::try_from(c.to_string().repeat(64)).unwrap();
    let template: Template = serde_json::from_value(json!({
        "template_id": "web-v1", "base_disk": "/a/base.ext4", "base_disk_sha256": digest('1'), "scratch_disk": "/a/s.ext4",
        "scratch_disk_sha256": digest('2'), "blobs": {"web": "/a/w"}, "blob_sha256": {"web": digest('3')},
        "endpoints": {"http": 8080, "admin": 9000}, "pool_target": 2, "snapshot": "lazy",
        "snapshot_warmup": [{"endpoint": "http", "path": "/"}],
        "manifest": {
            "containers": [{"name": "web", "blob": "web", "args": ["sh", "-c", "a && b <c>"], "env": {"B": "2", "A": "1"}}],
            "readiness": [{"name": "http", "tcp_port": 8080}],
        },
    }))
    .unwrap();
    let (kernel, other_kernel) = (digest('e'), Sha256Hex::try_from(EMPTY_SHA256.to_owned()).unwrap());
    // pinned on purpose: change the encoding and every host refuses the templates it already pinned.
    assert_eq!(template.fingerprint(&kernel, "init=/sbin/init"), "609219da078ad8703cce78b02e58b5949692d5d139188934d839dcc75426498f");

    let mut moved = template.clone();
    (moved.pool_target, moved.snapshot, moved.base_disk) = (0, None, "/b/base.ext4".into());
    moved.blobs.insert("web".into(), "/b/w".into());
    assert_eq!(moved.fingerprint(&kernel, "x"), template.fingerprint(&kernel, "x"), "paths and boot strategy aren't identity");
    let mut bigger = template.clone();
    bigger.mem_mib = 1024;
    assert_ne!(bigger.fingerprint(&kernel, "x"), template.fingerprint(&kernel, "x"));
    assert_ne!(template.fingerprint(&other_kernel, "x"), template.fingerprint(&kernel, "x"));
    assert_ne!(template.fingerprint(&kernel, "y"), template.fingerprint(&kernel, "x"));
    let mut closed = template.clone();
    closed.endpoints.remove("admin");
    assert_ne!(closed.fingerprint(&kernel, "x"), template.fingerprint(&kernel, "x"));
}
