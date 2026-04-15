//! Host sizing roost does for its guests: the conntrack table, the hugepage pool, and console logs.

use std::io;
use std::num::NonZeroU32;

use super::*;

const CONNTRACK: &str = "/proc/sys/net/netfilter";
/// Headroom for the host's own flows on top of the guests' caps.
const CONNTRACK_NODE_RESERVE: u64 = 8192;
const CONNTRACK_BUCKET_RATIO: u64 = 4;
pub(super) const NR_HUGEPAGES: &str = "/proc/sys/vm/nr_hugepages";
pub(super) const FREE_HUGEPAGES: &str = "/sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages";
const HUGEPAGE_SLACK: u64 = 64;
const DROP_CACHES: &str = "/proc/sys/vm/drop_caches";

/// Makes hugepage pool growth take turns. Otherwise boots racing to read-then-write it could land a smaller target last
/// and shrink the pool under a guest.
static HUGEPAGES: Mutex<()> = Mutex::new(());

pub(super) fn read_u64(path: &Path) -> Result<u64> {
    let data = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    data.trim().parse().with_context(|| format!("parse {}", path.display()))
}

fn write(path: &Path, value: u64) -> Result<()> {
    fs::write(path, value.to_string()).with_context(|| format!("write {}", path.display()))
}

/// 1.5x every slot's connection cap, plus whichever's bigger: what's already tracked, or a reserve for the host.
fn conntrack_want(slots: u32, conn_limit: u32, in_use: u64) -> u64 {
    u64::from(slots) * u64::from(conn_limit) * 3 / 2 + in_use.max(CONNTRACK_NODE_RESERVE)
}

impl<D: Driver + 'static, H: Host> Manager<D, H> {
    /// Raises `nf_conntrack_max` and its hash buckets so every guest at its connection cap still fits. Never lowers
    /// them.
    pub(super) fn ensure_conntrack(&self, log_steady: bool) {
        if self.cfg.conntrack_sizing_disabled {
            return;
        }
        let Some(limit) = self.cfg.templates.iter().filter_map(|t| t.conn_limit).map(NonZeroU32::get).max() else { return };
        let dir = Path::new(CONNTRACK);
        let read = || anyhow::Ok((read_u64(&dir.join("nf_conntrack_count"))?, read_u64(&dir.join("nf_conntrack_max"))?));
        let (in_use, max) = match read() {
            Ok(counts) => counts,
            Err(err) => return tracing::error!(error = format!("{err:#}"), "conntrack sizing"),
        };
        let want = conntrack_want(self.capacity, limit, in_use);
        if max >= want {
            if log_steady {
                tracing::info!(max, want, slots = self.capacity, conn_limit = limit, in_use, "nf_conntrack_max covers the guest cap");
            }
            return;
        }
        if let Err(err) = write(&dir.join("nf_conntrack_max"), want) {
            return tracing::error!(error = format!("{err:#}"), "raise nf_conntrack_max");
        }
        let buckets = dir.join("nf_conntrack_buckets");
        if let Ok(have) = read_u64(&buckets)
            && have < want / CONNTRACK_BUCKET_RATIO
            && let Err(err) = write(&buckets, want / CONNTRACK_BUCKET_RATIO)
        {
            tracing::error!(error = format!("{err:#}"), "raise nf_conntrack_buckets");
        }
        tracing::info!(max, want, slots = self.capacity, conn_limit = limit, in_use, "raised nf_conntrack_max");
    }
}

/// Grows the 2M hugepage pool to cover every reserved guest. Runs off the runtime since the kernel compacts memory to
/// do it.
pub(super) async fn ensure_hugepages(committed_mib: u32) -> Result<()> {
    let want = u64::from(committed_mib) / 2 + HUGEPAGE_SLACK;
    tokio::task::spawn_blocking(move || grow_hugepages(Path::new(NR_HUGEPAGES), Path::new(DROP_CACHES), want)).await?
}

/// Grows the pool at `nr` to `want`, never shrinks it. If fragmentation gets in the way, drops caches and retries once.
fn grow_hugepages(nr: &Path, drop_caches: &Path, want: u64) -> Result<()> {
    let _turn = HUGEPAGES.lock().expect("never poisoned");
    if read_u64(nr)? >= want {
        return Ok(());
    }
    for attempt in 0..2 {
        write(nr, want)?;
        if read_u64(nr)? >= want {
            return Ok(());
        }
        if attempt == 0 {
            // best effort. The retry tells us if it helped.
            let _ = fs::write(drop_caches, "3");
        }
    }
    anyhow::bail!("could not reserve {want} hugepages")
}

/// Rotates a console log past `max` bytes to `.1`. The vmm holds an `O_APPEND` fd, so we copy then truncate, and
/// anything written in between is lost.
pub(super) fn cap_console(path: &Path, max: u64) -> Result<()> {
    match fs::metadata(path) {
        Ok(meta) if meta.len() < max => return Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).context("stat console"),
        Ok(_) => {}
    }
    let mut src = File::open(path).context("open console")?;
    let rotated = path.with_extension("log.1");
    let mut dst =
        OpenOptions::new().create(true).truncate(true).write(true).mode(0o600).open(&rotated).context("create rotated console")?;
    io::copy(&mut src, &mut dst).context("rotate console")?;
    dst.sync_all().context("rotate console")?;
    File::options().write(true).open(path).and_then(|f| f.set_len(0)).context("truncate console")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conntrack_covers_slot_caps() {
        assert_eq!(conntrack_want(2, 4096, 100), 2 * 4096 * 3 / 2 + 8192);
        assert_eq!(conntrack_want(2, 4096, 20_000), 2 * 4096 * 3 / 2 + 20_000);
    }

    #[test]
    fn hugepages_only_grow() {
        let dir = tempfile::tempdir().unwrap();
        let (nr, drop_caches) = (dir.path().join("nr_hugepages"), dir.path().join("drop_caches"));
        fs::write(&nr, "10\n").unwrap();
        grow_hugepages(&nr, &drop_caches, 4).unwrap();
        assert_eq!(read_u64(&nr).unwrap(), 10);
        grow_hugepages(&nr, &drop_caches, 32).unwrap();
        assert_eq!(read_u64(&nr).unwrap(), 32);
        assert!(!drop_caches.exists(), "caches are dropped only when the kernel falls short");
    }

    #[test]
    fn concurrent_hugepage_growth_keeps_max() {
        let dir = tempfile::tempdir().unwrap();
        let (nr, drop_caches) = (dir.path().join("nr_hugepages"), dir.path().join("drop_caches"));
        fs::write(&nr, "0").unwrap();
        std::thread::scope(|s| {
            for want in 1..=32 {
                let (nr, drop_caches) = (&nr, &drop_caches);
                s.spawn(move || grow_hugepages(nr, drop_caches, want).unwrap());
            }
        });
        assert_eq!(read_u64(&nr).unwrap(), 32);
    }

    #[test]
    fn consoles_rotate_past_cap() {
        let dir = tempfile::tempdir().unwrap();
        let console = dir.path().join("console.log");
        cap_console(&console, 4).unwrap();
        fs::write(&console, "abc").unwrap();
        cap_console(&console, 4).unwrap();
        assert_eq!(fs::read_to_string(&console).unwrap(), "abc");
        fs::write(&console, "abcdef").unwrap();
        cap_console(&console, 4).unwrap();
        assert_eq!(fs::read_to_string(&console).unwrap(), "");
        assert_eq!(fs::read_to_string(dir.path().join("console.log.1")).unwrap(), "abcdef");
    }
}
