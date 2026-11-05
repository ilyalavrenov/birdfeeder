use serde_json::{json, to_value};

use super::*;

#[test]
fn huge_pages_use_firecrackers_names() {
    let config = MachineConfiguration {
        cpu_template: None,
        huge_pages: MachineConfigurationHugePages::X2m,
        mem_size_mib: 512,
        smt: false,
        track_dirty_pages: false,
        vcpu_count: 1.try_into().unwrap(),
    };
    assert_eq!(
        to_value(&config).unwrap(),
        json!({"huge_pages": "2M", "mem_size_mib": 512, "smt": false, "track_dirty_pages": false, "vcpu_count": 1})
    );
}

#[test]
fn unset_options_are_omitted() {
    let load = SnapshotLoadParams {
        snapshot_path: "/snap/vmstate".into(),
        mem_backend: Some(MemoryBackend { backend_path: "/run/uffd.sock".into(), backend_type: MemoryBackendBackendType::Uffd }),
        resume_vm: Some(true),
        clock_realtime: None,
        enable_diff_snapshots: None,
        huge_pages: None,
        mem_file_path: None,
        network_overrides: Vec::new(),
        track_dirty_pages: None,
        vsock_override: None,
    };
    assert_eq!(
        to_value(&load).unwrap(),
        json!({"snapshot_path": "/snap/vmstate", "mem_backend": {"backend_path": "/run/uffd.sock", "backend_type": "Uffd"}, "resume_vm": true})
    );
}

#[test]
fn actions_and_states_are_pascal_case() {
    assert_eq!(
        to_value(InstanceActionInfo { action_type: InstanceActionInfoActionType::InstanceStart }).unwrap(),
        json!({"action_type": "InstanceStart"})
    );
    assert_eq!(to_value(Vm { state: VmState::Paused }).unwrap(), json!({"state": "Paused"}));
}

#[test]
fn drives_fill_in_firecrackers_defaults() {
    let drive: Drive =
        serde_json::from_value(json!({"drive_id": "rootfs", "is_root_device": true, "path_on_host": "/rootfs.ext4"})).unwrap();
    assert_eq!(drive.io_engine, DriveIoEngine::Sync);
    assert_eq!(drive.cache_type, DriveCacheType::Unsafe);
    assert!(drive.rate_limiter.is_none());
}
