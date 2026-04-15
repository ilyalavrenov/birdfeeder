use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::num::{NonZeroU64, NonZeroUsize};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use memmap2::{Mmap, MmapMut};
use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::poll::PollFlags;
use signal_hook::consts::{SIGINT, SIGTERM, SIGUSR1};
use tracing::{error, info, warn};

use crate::layout::{Layout, PageSet, PageSize};
use crate::mem_file::MemFile;
use crate::remote::{FetchId, Fetched, Priority, Remote, Retry, Shared};
use crate::stats::Stats;
use crate::sys::PollSet;
use crate::uffd::{self, CopyErr, Event};
use crate::{fetch, handshake, manifest, working_set};

const POLL_TIMEOUT: Duration = Duration::from_secs(1);
const MSG_BATCH: usize = 64;
/// The guest resumes before prefetch is done, so prefetch stops to serve faults every this many
/// pages. A vCPU faulting outside the early working set waits a few copies, not the whole set.
const PREFETCH_FAULT_CHECK: usize = 16;

pub enum Source {
    Local(PathBuf),
    /// A URL serving the memory file's byte ranges, such as a presigned S3 GET. Every chunk with
    /// data gets fetched in the background, so the guest is done with the URL before it expires.
    Remote {
        url: String,
        manifest: PathBuf,
        /// the working set's pages packed in its order.
        pack_url: Option<String>,
        /// how much one fetch reads, rounded up to whole guest pages.
        chunk_size: NonZeroU64,
        fetchers: NonZeroUsize,
    },
}

pub struct Record {
    /// where SIGUSR1 writes the pages faulted so far, after which recording stops.
    pub working_set: PathBuf,
    /// where those pages' contents go too, packed in the same order.
    pub pack: Option<PathBuf>,
}

pub enum Mode {
    /// populate every page right after the handshake and return instead of serving faults.
    FaultAll,
    Serve {
        /// a working set to populate right after the handshake, serving faults as they arrive.
        prefetch: Option<PathBuf>,
        /// recording needs a local memory file: a chunk landing fills pages the guest never faulted.
        record: Option<Record>,
    },
}

pub struct Options {
    pub socket: PathBuf,
    pub source: Source,
    pub mode: Mode,
    pub stats_every: Duration,
}

/// Serves one VMM until it exits, or populates all pages and returns in [`Mode::FaultAll`].
pub fn serve(o: &Options) -> Result<()> {
    let conn = handshake::accept(&o.socket)?;
    let mut h = Handler::new(conn, o)?;
    info!(
        regions = h.layout.regions.len(),
        page_size = h.layout.page_size.get(),
        mem_bytes = h.layout.size(),
        data_bytes = h.data_bytes(),
        fault_all = matches!(o.mode, Mode::FaultAll),
        remote = matches!(h.backing, Backing::Remote(_)),
        "handshake complete"
    );
    if !o.stats_every.is_zero() {
        let (stats, every) = (Arc::clone(&h.stats), o.stats_every);
        thread::spawn(move || {
            loop {
                thread::sleep(every);
                stats.log("uffd stats");
            }
        });
    }
    let result = match h.serve_mode(&o.mode) {
        // only an error so every copy path unwinds at once
        Err(err) if err.downcast_ref::<CopyErr>() == Some(&CopyErr::VmmGone) => {
            info!("vmm exited while memory was being copied");
            Ok(())
        }
        result => result,
    };
    h.join_publishing();
    h.stats.log("handler exiting");
    result
}

enum Backing {
    /// shared with the thread that publishes a recording's pack.
    Local(Arc<MemFile>),
    Remote(Remote),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Progress {
    Done,
    /// `UFFDIO_COPY` returns EAGAIN until pending remove events are drained.
    Blocked,
}

/// Recording until SIGUSR1. `seen` dedupes `order`, which keeps first-touch order for prefetch.
struct Recording {
    working_set: PathBuf,
    pack: Option<PathBuf>,
    seen: HashSet<u64>,
    order: Vec<u64>,
}

/// What the poll loop watches beyond the uffd and finished fetches.
#[derive(Clone, Copy)]
enum Watch<'s> {
    /// nothing else, while populating fetches everything.
    Fetches,
    /// the VMM exiting, and these signals when the process has them.
    Vmm(Option<&'s Signals>),
}

/// Which of the watched descriptors are ready.
#[expect(clippy::struct_excessive_bools, reason = "one independent flag per watched descriptor")]
struct Ready {
    faults: bool,
    fetched: bool,
    vmm: bool,
    stop: bool,
    finish: bool,
}

/// Self-pipes the signal handlers write to, so the poll loop wakes up on signals.
struct Signals {
    stop: UnixStream,
    finish: UnixStream,
}

impl Signals {
    fn register() -> Result<Self> {
        let pipe = |signals: &[i32]| -> Result<UnixStream> {
            let (read, write) = UnixStream::pair().context("signal pipe")?;
            read.set_nonblocking(true)?;
            for &sig in signals {
                signal_hook::low_level::pipe::register(sig, write.try_clone()?).context("register signal")?;
            }
            Ok(read)
        };
        Ok(Self { stop: pipe(&[SIGTERM, SIGINT])?, finish: pipe(&[SIGUSR1])? })
    }
}

struct Handler {
    layout: Layout,
    backing: Backing,
    zero: Mmap,
    removed: PageSet,
    uffd: OwnedFd,
    conn: UnixStream,
    pending: Vec<u64>,
    stats: Arc<Stats>,
    recording: Option<Recording>,
    publishing: Option<thread::JoinHandle<()>>,
}

impl Handler {
    fn new(conn: UnixStream, o: &Options) -> Result<Self> {
        let (body, uffd) = handshake::receive(&conn)?;
        let stats = Arc::new(Stats::default());
        let (layout, backing) = match &o.source {
            Source::Local(path) => {
                let mem = MemFile::open(path)?;
                (Layout::parse(&body, mem.size())?, Backing::Local(Arc::new(mem)))
            }
            Source::Remote { url, manifest, pack_url, chunk_size, fetchers } => {
                let (size, data) = manifest::decode(&fs::read(manifest).context("read manifest")?)?;
                let layout = Layout::parse(&body, size)?;
                let chunk = chunk_size.get().next_multiple_of(layout.page_size.get());
                let remote = Remote::start(url, pack_url.clone(), size, data, chunk, *fetchers, Arc::clone(&stats))?;
                (layout, Backing::Remote(remote))
            }
        };
        // hugetlb has no UFFDIO_ZEROPAGE, so we copy zeros from an untouched anonymous page
        let zero = MmapMut::map_anon(layout.page_size.bytes()).and_then(MmapMut::make_read_only).context("mmap zero page")?;
        // the drain loop needs this, no matter what firecracker set on the shared file description
        let flags = OFlag::from_bits_retain(fcntl(&uffd, FcntlArg::F_GETFL).context("get uffd flags")?);
        fcntl(&uffd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).context("set uffd nonblocking")?;
        Ok(Self {
            removed: PageSet::new(layout.page_size),
            layout,
            backing,
            zero,
            uffd,
            conn,
            pending: Vec::new(),
            stats,
            recording: None,
            publishing: None,
        })
    }

    fn data_bytes(&self) -> u64 {
        match &self.backing {
            Backing::Local(m) => m.data.bytes(),
            Backing::Remote(r) => r.shared.data.bytes(),
        }
    }

    fn serve_mode(&mut self, mode: &Mode) -> Result<()> {
        let Mode::Serve { prefetch, record } = mode else { return self.populate() };
        if let Some(path) = prefetch {
            self.prefetch(path)?;
        }
        if let Some(r) = record {
            self.recording =
                Some(Recording { working_set: r.working_set.clone(), pack: r.pack.clone(), seen: HashSet::new(), order: Vec::new() });
        }
        if let Backing::Remote(r) = &self.backing {
            r.shared.request_all();
        }
        self.run(Some(&Signals::register()?))
    }

    fn run(&mut self, signals: Option<&Signals>) -> Result<()> {
        loop {
            let ready = self.wait(Watch::Vmm(signals))?;
            if ready.stop {
                return Ok(());
            }
            if let Some(s) = signals
                && ready.finish
            {
                let _ = (&s.finish).read(&mut [0; 64]);
                self.finish_recording();
            }
            if ready.vmm && self.vmm_gone() {
                info!("vmm closed the handshake socket");
                return Ok(());
            }
            self.handle_ready(&ready)?;
        }
    }

    /// Polls the uffd, finished fetches when remote, and whatever `watch` adds. The set's rebuilt
    /// every time because it borrows fds from `self`, and serving what's ready mutates `self`.
    fn wait(&self, watch: Watch<'_>) -> Result<Ready> {
        let mut fds = PollSet::default();
        let faults = fds.add(self.uffd.as_fd(), PollFlags::POLLIN);
        let fetched = match &self.backing {
            Backing::Remote(r) => Some(fds.add(r.shared.wake_fd(), PollFlags::POLLIN)),
            Backing::Local(_) => None,
        };
        let (vmm, signals) = match watch {
            Watch::Fetches => (None, None),
            Watch::Vmm(signals) => (
                // EOF already polls as readable. POLLRDHUP adds nothing, and nix can't decode it
                Some(fds.add(self.conn.as_fd(), PollFlags::POLLIN)),
                signals.map(|s| (fds.add(s.stop.as_fd(), PollFlags::POLLIN), fds.add(s.finish.as_fd(), PollFlags::POLLIN))),
            ),
        };
        fds.wait(POLL_TIMEOUT)?;
        Ok(Ready {
            faults: fds.readable(faults),
            fetched: fetched.is_some_and(|s| fds.readable(s)),
            vmm: vmm.is_some_and(|s| fds.ready(s)),
            stop: signals.is_some_and(|(stop, _)| fds.ready(stop)),
            finish: signals.is_some_and(|(_, finish)| fds.ready(finish)),
        })
    }

    fn handle_ready(&mut self, ready: &Ready) -> Result<()> {
        if ready.faults {
            self.serve_faults()?;
        }
        if ready.fetched
            && let Backing::Remote(r) = &self.backing
        {
            let shared = Arc::clone(&r.shared);
            return self.load_fetched(&shared);
        }
        Ok(())
    }

    /// Firecracker never writes to this socket again. EOF means the VMM exited.
    fn vmm_gone(&self) -> bool {
        match (&self.conn).read(&mut [0]) {
            Ok(n) => n == 0,
            Err(e) => !matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted),
        }
    }

    fn serve_faults(&mut self) -> Result<()> {
        self.drain()?;
        let mut i = 0;
        while i < self.pending.len() {
            let addr = self.pending[i];
            self.note(addr);
            match self.serve_page(addr)? {
                Progress::Done => i += 1,
                Progress::Blocked => self.drain()?,
            }
        }
        self.pending.clear();
        Ok(())
    }

    fn drain(&mut self) -> Result<()> {
        let mut buf = [0; MSG_BATCH * uffd::MSG_SIZE];
        loop {
            let n = match nix::unistd::read(&self.uffd, &mut buf) {
                Ok(n) => n,
                Err(Errno::EAGAIN) => return Ok(()),
                Err(Errno::EINTR) => continue,
                Err(e) => return Err(e).context("read uffd"),
            };
            for msg in buf[..n].as_chunks::<{ uffd::MSG_SIZE }>().0 {
                self.event(Event::parse(msg));
            }
        }
    }

    fn event(&mut self, event: Event) {
        match event {
            Event::Pagefault(addr) => {
                self.stats.faults.add(1);
                self.pending.push(addr);
            }
            Event::Remove(range) => {
                self.stats.removes.add(1);
                self.removed.remove(range);
            }
            Event::Other(event) => warn!(event, "unexpected uffd event"),
        }
    }

    fn serve_page(&self, addr: u64) -> Result<Progress> {
        let Some((page, off)) = self.layout.locate(addr) else {
            bail!("fault at {addr:#x} outside guest memory");
        };
        let ps = self.layout.page_size;
        let removed = self.removed.has(page);
        let data = match &self.backing {
            Backing::Remote(r) if !removed && r.shared.data.overlaps(off..off + ps.get()) => {
                // the copy wakes the faulting vCPU, and a fault on a page already copied is stale
                r.fault(off);
                return Ok(Progress::Done);
            }
            Backing::Local(m) if !removed => m.page(off, ps),
            _ => None,
        };
        let progress = copy_page(&self.uffd, page, data.unwrap_or(&self.zero[..]))?;
        if progress == Progress::Done {
            if data.is_some() { &self.stats.copied_bytes } else { &self.stats.zeroed_bytes }.add(ps.get());
        }
        Ok(progress)
    }

    /// Copies one page in before anything faults on it, draining events that block the copy.
    fn populate_page(&mut self, page: u64) -> Result<()> {
        while self.serve_page(page)? == Progress::Blocked {
            self.drain()?;
        }
        Ok(())
    }

    /// Copies `src` to `dst`, skipping pages that are already in, either because a fault zeroed a
    /// hole or a vCPU raced the copy.
    fn copy_range(&self, mut dst: u64, mut src: &[u8]) -> Result<Progress> {
        while !src.is_empty() {
            let (copied, n) = match uffd::copy(self.uffd.as_fd(), dst, src) {
                Ok(()) => (src.len() as u64, src.len() as u64),
                // resuming tells us what stopped a partial copy
                Err(CopyErr::Again { copied }) if copied > 0 => (copied, copied),
                Err(CopyErr::Again { .. }) => return Ok(Progress::Blocked),
                Err(CopyErr::Exists) => (0, self.layout.page_size.get()),
                Err(e) => return Err(copy_error(e, dst, src)),
            };
            self.stats.copied_bytes.add(copied);
            dst += n;
            src = &src[usize::try_from(n).expect("copied bytes fit in the source")..];
        }
        Ok(Progress::Done)
    }

    fn note(&mut self, addr: u64) {
        let Some(rec) = &mut self.recording else { return };
        if let Some((_, off)) = self.layout.locate(addr)
            && rec.seen.insert(off)
        {
            rec.order.push(off);
        }
    }

    /// Publishes the working set on its own thread, since the pack can be several GiB and the guest
    /// keeps faulting meanwhile. If it fails, later restores just lose their prefetch.
    fn finish_recording(&mut self) {
        let Some(rec) = self.recording.take() else { return };
        let mem = match &self.backing {
            Backing::Local(mem) => Some(Arc::clone(mem)),
            Backing::Remote(_) => None,
        };
        let ps = self.layout.page_size;
        let publish = move || {
            // the working set showing up is how we say recording's done, so write the pack first
            let written = write_pack(&rec, mem.as_deref(), ps)
                .and_then(|()| working_set::write_atomic(&rec.working_set, &working_set::encode(&rec.order)));
            match written {
                Ok(()) => info!(pages = rec.order.len(), bytes = rec.order.len() as u64 * ps.get(), "recorded working set"),
                Err(err) => error!(err = format!("{err:#}"), "write working set"),
            }
        };
        match thread::Builder::new().name("publish-working-set".into()).spawn(publish) {
            Ok(t) => self.publishing = Some(t),
            Err(err) => error!(err = %err, "start working set writer"),
        }
    }

    /// Waits for a recording to finish publishing. It's still useful even though the VMM exited.
    fn join_publishing(&mut self) {
        if let Some(t) = self.publishing.take() {
            // a panic there already reported itself and only cost us the recording
            let _ = t.join();
        }
    }

    fn prefetch(&mut self, path: &Path) -> Result<()> {
        let start = Instant::now();
        let offsets = working_set::read(path)?;
        let pages = offsets
            .iter()
            .map(|&off| self.layout.address(off).with_context(|| format!("working set offset {off:#x} outside guest memory")))
            .collect::<Result<Vec<_>>>()?;
        if let Backing::Remote(remote) = &mut self.backing {
            remote.queue_working_set(&offsets, self.layout.page_size);
            info!(pages = offsets.len(), fetches = remote.shared.pending(), packed = remote.has_pack(), "queued working set");
            return Ok(());
        }
        for (i, page) in pages.into_iter().enumerate() {
            if i % PREFETCH_FAULT_CHECK == 0 {
                self.serve_faults()?;
            }
            self.populate_page(page)?;
        }
        info!(pages = offsets.len(), ms = start.elapsed().as_millis(), "prefetched working set");
        Ok(())
    }

    fn populate(&mut self) -> Result<()> {
        let start = Instant::now();
        if let Backing::Remote(r) = &self.backing {
            let shared = Arc::clone(&r.shared);
            self.fetch_all(&shared)?;
        }
        let step = self.layout.page_size.bytes();
        let pages: Vec<u64> =
            self.layout.regions.iter().flat_map(|r| (r.base_host_virt_addr..r.base_host_virt_addr + r.size).step_by(step)).collect();
        for page in pages {
            self.populate_page(page)?;
        }
        info!(ms = start.elapsed().as_millis(), "populated all guest memory");
        Ok(())
    }

    /// Copies in every chunk with data, serving faults as it goes. Holes are left to populate.
    fn fetch_all(&mut self, shared: &Shared) -> Result<()> {
        // the guest waits on all of it, so it's urgent: every fetcher takes it, and a failure is fatal
        for c in 0..shared.chunks() {
            shared.request(c, Priority::Urgent);
        }
        while shared.pending() > 0 {
            let ready = self.wait(Watch::Fetches)?;
            self.handle_ready(&ready)?;
        }
        Ok(())
    }

    /// Copies every finished fetch into the guest, then serves faults that queued up meanwhile.
    fn load_fetched(&mut self, shared: &Shared) -> Result<()> {
        for f in shared.take_finished() {
            self.copy_fetched(shared, f)?;
        }
        if shared.just_loaded() {
            info!(
                ms = shared.started.elapsed().as_millis(),
                fetched_bytes = self.stats.fetched_bytes.get(),
                abandoned_chunks = shared.abandoned(),
                "remote memory loaded"
            );
        }
        if self.pending.is_empty() { Ok(()) } else { self.serve_faults() }
    }

    fn copy_fetched(&mut self, shared: &Shared, f: Fetched) -> Result<()> {
        let buf = match f.buf {
            Ok(buf) => buf,
            Err(err) => return self.fetch_failed(shared, f.id, f.priority, err),
        };
        match f.id {
            FetchId::Piece(p) => self.copy_pack_piece(shared.pack_piece(p).1, &buf)?,
            FetchId::Chunk(c) => {
                let start = shared.chunk_range(c).start;
                // a pending remove blocks the copy. draining it can also drop pages from the runs
                while self.copy_runs(start, &buf)? == Progress::Blocked {
                    self.drain()?;
                }
            }
        }
        shared.mark_done(f.id);
        Ok(())
    }

    /// A fetch nobody was waiting on gets retried later, so one bad stretch of S3 doesn't kill a
    /// guest that might never touch those pages.
    fn fetch_failed(&self, shared: &Shared, id: FetchId, priority: Priority, err: anyhow::Error) -> Result<()> {
        self.stats.fetch_failures.add(1);
        match shared.failed(id, priority, fetch::is_refused(&err)) {
            Retry::Fatal => Err(err),
            Retry::Later(delay) => {
                warn!(fetch = %id, retry_ms = delay.as_millis(), err = format!("{err:#}"), "background fetch failed");
                Ok(())
            }
            Retry::Abandoned => {
                warn!(fetch = %id, err = format!("{err:#}"), "background fetch abandoned until a fault needs it");
                Ok(())
            }
        }
    }

    /// Copies each working-set page in a piece of the pack to its address. Their chunks show up
    /// later in the background and skip over them.
    fn copy_pack_piece(&mut self, pages: &[u64], buf: &[u8]) -> Result<()> {
        let ps = self.layout.page_size.bytes();
        let mut i = 0;
        while i < pages.len() {
            let Some(addr) = self.layout.address(pages[i]) else {
                bail!("working set offset {:#x} outside guest memory", pages[i]);
            };
            // a pending remove blocks the copy, and may be for this page
            if !self.removed.has(addr) && self.copy_range(addr, &buf[i * ps..(i + 1) * ps])? == Progress::Blocked {
                self.drain()?;
                continue;
            }
            i += 1;
        }
        Ok(())
    }

    /// Copies `buf`, the memory file from `start`, as runs of contiguous guest addresses, leaving
    /// out pages the guest removed, since those have to read as zeros and not the snapshot.
    fn copy_runs(&self, start: u64, buf: &[u8]) -> Result<Progress> {
        let step = self.layout.page_size.bytes();
        // the current run: guest address, then offset and length in buf
        let mut run: Option<(u64, usize, usize)> = None;
        for i in (0..buf.len()).step_by(step) {
            let off = start + i as u64;
            let Some(addr) = self.layout.address(off) else {
                bail!("chunk offset {off:#x} outside guest memory");
            };
            let flushed = if self.removed.has(addr) {
                run.take()
            } else if let Some((dst, _, n)) = &mut run
                && addr == *dst + *n as u64
            {
                *n += step;
                continue;
            } else {
                run.replace((addr, i, step))
            };
            if self.copy_run(buf, flushed)? == Progress::Blocked {
                return Ok(Progress::Blocked);
            }
        }
        self.copy_run(buf, run)
    }

    fn copy_run(&self, buf: &[u8], run: Option<(u64, usize, usize)>) -> Result<Progress> {
        match run {
            Some((dst, from, n)) => self.copy_range(dst, &buf[from..from + n]),
            None => Ok(Progress::Done),
        }
    }
}

/// Writes the recorded pages' contents in recording order, if a pack was asked for.
fn write_pack(rec: &Recording, mem: Option<&MemFile>, ps: PageSize) -> Result<()> {
    let Some(path) = &rec.pack else { return Ok(()) };
    let Some(mem) = mem else { bail!("a pack needs a local memory file") };
    let zero = vec![0; ps.bytes()];
    working_set::write_atomic_with(path, |w| rec.order.iter().try_for_each(|&off| w.write_all(mem.page(off, ps).unwrap_or(&zero))))
}

/// Copies one whole page. EEXIST means another vCPU already handled the fault.
fn copy_page(uffd: &OwnedFd, dst: u64, src: &[u8]) -> Result<Progress> {
    match uffd::copy(uffd.as_fd(), dst, src) {
        Ok(()) | Err(CopyErr::Exists) => Ok(Progress::Done),
        Err(CopyErr::Again { .. }) => Ok(Progress::Blocked),
        Err(e) => Err(copy_error(e, dst, src)),
    }
}

/// A copy failure the caller can't handle. [`CopyErr::VmmGone`] stays as-is for [`serve`] to find.
fn copy_error(e: CopyErr, dst: u64, src: &[u8]) -> anyhow::Error {
    match e {
        CopyErr::Other(errno) => anyhow::Error::new(errno).context(format!("UFFDIO_COPY {dst:#x}+{:#x}", src.len())),
        e => anyhow::Error::new(e),
    }
}

#[cfg(test)]
#[path = "handler_tests.rs"]
mod tests;
