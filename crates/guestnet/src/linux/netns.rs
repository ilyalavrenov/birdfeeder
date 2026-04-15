//! Named network namespaces, pinned under /var/run/netns like `ip netns`.
//!
//! Joining a namespace is per thread, so the work runs on a throwaway thread spawned just for it. Nothing ever has to
//! switch a thread back, and a pooled thread can't get stuck in a guest's namespace.

use std::fs::File;
use std::future::Future;
use std::io;
use std::path::Path;

use anyhow::Context as _;
use nix::errno::Errno;
use nix::fcntl::{OFlag, open};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sched::{CloneFlags, setns, unshare};
use nix::sys::stat::Mode;

use crate::{NETNS_DIR, NETNS_PREFIX, netns_path};

async fn on_fresh_thread<T: Send + 'static>(f: impl FnOnce() -> anyhow::Result<T> + Send + 'static) -> anyhow::Result<T> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("guestnet-netns".to_owned())
        .spawn(move || {
            let _ = tx.send(f());
        })
        .context("spawn netns thread")?;
    rx.await.context("netns thread panicked")?
}

/// Runs `f` on a current-thread runtime inside the namespace at `path`. Any sockets it opens and processes it spawns
/// belong to that namespace.
pub(super) async fn run_in<F, Fut, T>(path: &Path, f: F) -> anyhow::Result<T>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = anyhow::Result<T>>,
    T: Send + 'static,
{
    let ns = File::open(path).with_context(|| format!("open {}", path.display()))?;
    on_fresh_thread(move || {
        setns(&ns, CloneFlags::CLONE_NEWNET).context("setns")?;
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().context("netns runtime")?;
        rt.block_on(f())
    })
    .await
}

/// A fresh namespace pinned at `path`, like `ip netns add`.
pub(super) async fn add(path: &Path) -> anyhow::Result<()> {
    let path = path.to_owned();
    on_fresh_thread(move || {
        unshare(CloneFlags::CLONE_NEWNET).context("unshare netns")?;
        mount_at(Path::new("/proc/thread-self/ns/net"), &path)
    })
    .await
}

/// Pins the namespace at `src` to `path`. Like iproute2, it makes the netns dir a shared mount first so the pin
/// propagates to mount namespaces cloned from this one.
pub(super) fn mount_at(src: &Path, path: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(NETNS_DIR).context("mkdir netns dir")?;
    let share = || mount(None::<&str>, NETNS_DIR, None::<&str>, MsFlags::MS_SHARED | MsFlags::MS_REC, None::<&str>);
    match share() {
        // not a mount point yet: bind it onto itself so it can be made shared.
        Err(Errno::EINVAL) => {
            mount(Some(NETNS_DIR), NETNS_DIR, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>)
                .with_context(|| format!("bind {NETNS_DIR}"))?;
            share().with_context(|| format!("share {NETNS_DIR}"))?;
        }
        r => r.with_context(|| format!("share {NETNS_DIR}"))?,
    }

    drop(
        open(path, OFlag::O_RDONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC, Mode::empty())
            .with_context(|| format!("create {}", path.display()))?,
    );
    if let Err(err) = mount(Some(src), path, None::<&str>, MsFlags::MS_BIND, None::<&str>) {
        let _ = std::fs::remove_file(path);
        return Err(err).with_context(|| format!("bind {} to {}", src.display(), path.display()));
    }
    Ok(())
}

/// Unpins a namespace. Fine if it's already gone. It lives on until its last process exits.
pub fn delete_netns(name: &str) -> anyhow::Result<()> {
    let path = netns_path(name);
    match umount2(&path, MntFlags::MNT_DETACH) {
        Ok(()) | Err(Errno::ENOENT | Errno::EINVAL) => {}
        Err(err) => return Err(err).with_context(|| format!("unmount {}", path.display())),
    }
    match std::fs::remove_file(&path) {
        Err(err) if err.kind() != io::ErrorKind::NotFound => Err(err).with_context(|| format!("remove {}", path.display())),
        _ => Ok(()),
    }
}

/// The pinned namespaces named like a session's, so recovery can sweep up orphans. No netns dir means nothing was ever
/// pinned.
pub fn list_netns() -> io::Result<Vec<String>> {
    let entries = match std::fs::read_dir(NETNS_DIR) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let mut names = Vec::new();
    for entry in entries {
        if let Ok(name) = entry?.file_name().into_string()
            && name.starts_with(NETNS_PREFIX)
        {
            names.push(name);
        }
    }
    Ok(names)
}
