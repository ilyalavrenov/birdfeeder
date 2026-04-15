//! Startup recovery: rebuild the session table from the state files, clean up guests that died while roost was down,
//! adopt the live ones, and sweep whatever no session owns.

use anyhow::{bail, ensure};

use super::*;

impl<D: Driver + 'static, H: Host> Manager<D, H> {
    pub(super) async fn reconcile(self: &Arc<Self>) -> Result<()> {
        let persisted = self.store.load()?;
        self.rebuild(persisted)?;
        let dead: Vec<_> =
            self.sessions().by_name.values().filter(|s| !self.driver.alive(&s.rec.instance)).map(|s| (s.rec.clone(), s.slot)).collect();
        for (rec, slot) in dead {
            tracing::info!(name = rec.name(), state = rec.state.as_str(), "cleaning dead session");
            if let Err(err) = self.teardown(&rec, slot).await {
                tracing::error!(name = rec.name(), error = format!("{err:#}"), "teardown dead session, adopting for reaper retry");
                if let Some(s) = self.sessions().by_name.get_mut(rec.name()) {
                    s.rec.state = State::Stopping;
                }
                continue;
            }
            let released = self.release_key(&mut self.sessions(), &rec);
            if let Some(released) = released {
                released.write().await?;
            }
            let gone = self.store.stage_remove(rec.name());
            gone.write().await?;
            let mut sessions = self.sessions();
            sessions.by_name.remove(rec.name());
            sessions.slots.remove(&slot.index);
        }
        self.sweep_orphans().await;
        let adopted: Vec<_> = self.sessions().by_name.keys().cloned().collect();
        for name in adopted {
            self.adopt(&name);
        }
        Ok(())
    }

    /// Admits the persisted sessions, and refuses state this config couldn't have written. A session has to keep its
    /// slot's name, addresses and ports, and can't have a generation newer than the generation file.
    fn rebuild(&self, persisted: Vec<Record>) -> Result<()> {
        let mut sessions = self.sessions();
        for rec in persisted {
            let name = rec.name().to_owned();
            let index = rec.instance.slot;
            let Some(generation) = NonZeroU64::new(rec.generation()) else { bail!("incompatible state for session {name:?}") };
            ensure!(
                rec.version == 1
                    && name == format!("{}-{index}", self.name_prefix)
                    && index < self.capacity
                    && rec.vcpus >= 1
                    && rec.mem_mib >= 1
                    && sessions.gens.get(&name).is_some_and(|g| *g >= generation.get()),
                "incompatible state for session {name:?}"
            );
            ensure!(!sessions.slots.contains(&index), "duplicate persisted slot {index}");
            let slot = Slot::new(self.cfg.subnet, index).context("slot outside the subnet")?;
            ensure!(
                rec.tap == slot.tap() && rec.netns == slot.netns() && rec.guest_ip == slot.guest && rec.gateway_ip == slot.gateway,
                "network configuration changed for session {name:?}"
            );
            let ports = u32::from(self.cfg.dnat_port_start) + index * ENDPOINT_BLOCK;
            ensure!(
                rec.endpoints.values().all(|e| (ports..ports + ENDPOINT_BLOCK).contains(&u32::from(e.host_port))),
                "port configuration changed for session {name:?}"
            );
            sessions.slots.insert(index);
            let id = SessionRef { name: name.clone(), generation };
            sessions.by_name.insert(name, Session { id, rec, slot, boot: None, teardown: Arc::default(), recorded: true });
        }
        Ok(())
    }

    fn adopt(self: &Arc<Self>, name: &str) {
        let (id, rec, slot, boot) = {
            let mut sessions = self.sessions();
            let Some(s) = sessions.by_name.get_mut(name) else { return };
            let boot = (s.rec.state == State::Booting).then(|| BootHandle::new(&self.stop));
            s.boot.clone_from(&boot);
            (s.id.clone(), s.rec.clone(), s.slot, boot)
        };
        tracing::info!(name, state = rec.state.as_str(), pid = rec.instance.pid, "adopting live session");
        if let Err(err) = self.driver.adopt(&rec.instance) {
            tracing::warn!(name, error = format!("{err:#}"), "adopt vmm telemetry");
        }
        if let Some(pid) = rec.instance.pid
            && let Err(err) = self.host.attach_netns(slot, pid)
        {
            tracing::error!(name, error = format!("{err:#}"), "attach netns");
        }
        let manager = Arc::clone(self);
        match (rec.state, boot) {
            (State::Booting, Some(boot)) => {
                self.tasks.spawn(async move { manager.resume_boot(id, rec, boot).await });
            }
            (State::Stopping, _) => {
                self.tasks.spawn(async move {
                    if let Err(err) = manager.destroy(&id).await {
                        tracing::error!(name = id.name, error = format!("{err:#}"), "finish interrupted delete");
                    }
                });
            }
            _ => {}
        }
    }

    /// Waits for a guest a previous roost was booting to become ready.
    async fn resume_boot(self: Arc<Self>, id: SessionRef, rec: Record, boot: BootHandle) {
        let _done = boot.done.clone().drop_guard();
        let ready = tokio::select! {
            biased;
            () = boot.cancel.cancelled() => return,
            ready = self.wait_ready(&rec, self.cfg.ready_timeout) => ready,
        };
        let name = id.name.as_str();
        let pooled = {
            let mut sessions = self.sessions();
            let Some(s) = sessions.get_mut(&id).filter(|s| s.rec.state == State::Booting) else { return };
            ready.is_ok().then(|| {
                s.rec.state = State::Pooled;
                s.rec.pooled_at = Some(SystemTime::now());
                self.store.stage(&s.rec)
            })
        };
        if let Some(pooled) = pooled {
            persist_logged(pooled, name, "persist resumed session").await;
        }
        if let Err(err) = ready {
            tracing::error!(name, error = format!("{err:#}"), "resumed boot never became ready");
            if let Err(err) = self.destroy(&id).await {
                tracing::error!(name, error = format!("{err:#}"), "destroy unresumable session");
            }
        }
    }

    /// Removes vmms, sandboxes, taps, namespaces, disks and run dirs no session owns. A crash between creating one and
    /// saving its session leaves it behind.
    async fn sweep_orphans(self: &Arc<Self>) {
        let (pids, instances, slots, disks, run_dirs) = {
            let sessions = self.sessions();
            let live = sessions.by_name.values();
            (
                live.clone().filter_map(|s| s.rec.instance.pid).collect::<Vec<_>>(),
                live.clone().map(|s| s.rec.instance.clone()).collect::<Vec<_>>(),
                live.clone().map(|s| s.slot).collect::<Vec<_>>(),
                live.clone().filter_map(|s| s.rec.instance.disk.file_name().map(ToOwned::to_owned)).collect::<BTreeSet<_>>(),
                live.filter_map(|s| self.run_dir(&s.rec.instance).file_name().map(ToOwned::to_owned)).collect::<BTreeSet<_>>(),
            )
        };
        let m = Arc::clone(self);
        // scans all of /proc
        off_runtime(move || m.host.kill_stray_vmms(&m.cfg.firecracker_bin, &m.cfg.run_dir, &pids)).await;
        if let Err(failures) = self.driver.sweep(&instances.iter().collect::<Vec<_>>()).await {
            self.teardown_errors("sweep vmm sandboxes", &failures);
        }
        self.host.sweep_networks(&slots).await;
        let m = Arc::clone(self);
        off_runtime(move || {
            sweep_dir(&m.cfg.state_dir.join("disks"), &disks);
            sweep_dir(&m.cfg.run_dir, &run_dirs);
        })
        .await;
    }
}

async fn off_runtime(work: impl FnOnce() + Send + 'static) {
    if let Err(err) = tokio::task::spawn_blocking(work).await {
        tracing::error!(error = %err, "sweep orphans");
    }
}

fn sweep_dir(dir: &Path, owned: &BTreeSet<std::ffi::OsString>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten().filter(|e| !owned.contains(&e.file_name())) {
        let path = entry.path();
        tracing::info!(path = %path.display(), "removing orphan");
        let removed = if entry.file_type().is_ok_and(|t| t.is_dir()) { fs::remove_dir_all(&path) } else { fs::remove_file(&path) };
        if let Err(err) = removed {
            tracing::error!(path = %path.display(), error = %err, "remove orphan");
        }
    }
}
