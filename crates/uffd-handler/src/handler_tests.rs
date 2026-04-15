use std::io::IoSlice;
use std::ops::Range;
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::mpsc;
use std::time::Duration;

use memmap2::MmapMut;
use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
use nix::unistd::{SysconfVar, sysconf};
use tempfile::TempDir;

use super::*;
use crate::fetch::tests::RangeServer;
use crate::remote::DEFAULT_FETCHERS;

// uapi/linux/userfaultfd.h
const UFFD_USER_MODE_ONLY: libc::c_long = 1;
const UFFD_API: u64 = 0xaa;
const UFFDIO_API: libc::Ioctl = 0xc018_aa3f;
const UFFDIO_REGISTER: libc::Ioctl = 0xc020_aa00;
const UFFDIO_REGISTER_MODE_MISSING: u64 = 1;

const REMOTE_PAGES: u64 = 1024;
const CHUNK_PAGES: u64 = 16;

fn page_size() -> u64 {
    sysconf(SysconfVar::PAGE_SIZE).unwrap().unwrap().cast_unsigned()
}

/// A distinct first byte on each page.
fn page_marks(pages: u64) -> Vec<u8> {
    let ps = page_size();
    let mut mem = vec![0; (pages * ps) as usize];
    for i in 0..pages {
        mem[(i * ps) as usize] = mark(i);
    }
    mem
}

fn mark(page: u64) -> u8 {
    (page % 255 + 1) as u8
}

fn options(source: Source) -> Options {
    Options { socket: PathBuf::new(), source, mode: Mode::Serve { prefetch: None, record: None }, stats_every: Duration::ZERO }
}

/// Fake guest: an anonymous region registered with a userfaultfd, handed to a handler over a
/// handshake the way Firecracker does it. `peer` is Firecracker's end of that socket.
struct Guest {
    region: MmapMut,
    peer: UnixStream,
    dir: TempDir,
}

impl Guest {
    /// Reads the first byte of each page on its own thread, like a vCPU faulting on them.
    fn read(&self, pages: &[u64]) -> mpsc::Receiver<(u64, u8)> {
        let (tx, rx) = mpsc::channel();
        let (base, ps, pages) = (self.region.as_ptr() as usize, page_size(), pages.to_vec());
        thread::spawn(move || {
            for p in pages {
                // SAFETY: the region outlives every test's reads, which the test waits for.
                let value = unsafe { std::ptr::read_volatile((base + (p * ps) as usize) as *const u8) };
                tx.send((p, value)).unwrap();
            }
        });
        rx
    }

    fn file(&self, name: &str, data: &[u8]) -> PathBuf {
        let path = self.dir.path().join(name);
        fs::write(&path, data).unwrap();
        path
    }
}

/// Registers `mem.len()` bytes with a userfaultfd and hands both to a handler. `None` when this
/// kernel or sandbox doesn't allow unprivileged userfaultfds.
fn guest(mem: &[u8], source: impl FnOnce(&Path) -> Options) -> Option<(Handler, Guest)> {
    // SAFETY: userfaultfd takes flags and returns a new descriptor or -1.
    let fd = unsafe { libc::syscall(libc::SYS_userfaultfd, libc::c_long::from(libc::O_CLOEXEC | libc::O_NONBLOCK) | UFFD_USER_MODE_ONLY) };
    if fd < 0 {
        let errno = Errno::last();
        assert!(matches!(errno, Errno::EPERM | Errno::ENOSYS), "userfaultfd: {errno}");
        eprintln!("skipping: userfaultfd unavailable: {errno}");
        return None;
    }
    // SAFETY: the syscall just gave us this fd and nobody else owns it.
    let uffd = unsafe { OwnedFd::from_raw_fd(i32::try_from(fd).unwrap()) };
    let mut api = [UFFD_API, 0, 0];
    // SAFETY: api is a live uffdio_api for the call.
    assert_eq!(unsafe { libc::ioctl(uffd.as_raw_fd(), UFFDIO_API, &raw mut api) }, 0, "UFFDIO_API");
    let region = MmapMut::map_anon(mem.len()).unwrap();
    let mut register = [region.as_ptr() as u64, mem.len() as u64, UFFDIO_REGISTER_MODE_MISSING, 0];
    // SAFETY: register is a live uffdio_register for the call.
    assert_eq!(unsafe { libc::ioctl(uffd.as_raw_fd(), UFFDIO_REGISTER, &raw mut register) }, 0, "UFFDIO_REGISTER");

    let (peer, conn) = UnixStream::pair().unwrap();
    let body =
        format!(r#"[{{"base_host_virt_addr":{},"size":{},"offset":0,"page_size":{}}}]"#, region.as_ptr() as u64, mem.len(), page_size());
    sendmsg::<()>(
        peer.as_raw_fd(),
        &[IoSlice::new(body.as_bytes())],
        &[ControlMessage::ScmRights(&[uffd.as_raw_fd()])],
        MsgFlags::empty(),
        None,
    )
    .unwrap();
    let guest = Guest { region, peer, dir: tempfile::tempdir().unwrap() };
    let h = Handler::new(conn, &source(&guest.file("mem", mem))).unwrap();
    Some((h, guest))
}

fn local(mem: &Path) -> Options {
    options(Source::Local(mem.to_owned()))
}

/// Serves `url` as the memory file, with a manifest next to the local copy saying `data` has data.
fn remote(url: String, chunk_size: u64, data: Vec<Range<u64>>) -> impl FnOnce(&Path) -> Options {
    remote_packed(url, None, chunk_size, data)
}

/// Like [`remote`], with the working set's pages packed at `pack_url`.
fn remote_packed(url: String, pack_url: Option<String>, chunk_size: u64, data: Vec<Range<u64>>) -> impl FnOnce(&Path) -> Options {
    move |mem| {
        let manifest = mem.with_file_name("manifest");
        fs::write(&manifest, manifest::encode(fs::metadata(mem).unwrap().len(), &data)).unwrap();
        let chunk_size = NonZeroU64::new(chunk_size).unwrap();
        options(Source::Remote { url, manifest, pack_url, chunk_size, fetchers: DEFAULT_FETCHERS })
    }
}

#[expect(clippy::single_range_in_vec_init, reason = "one extent, the whole file")]
fn whole(mem: &[u8]) -> Vec<Range<u64>> {
    vec![0..mem.len() as u64]
}

fn remote_shared(h: &Handler) -> Arc<Shared> {
    let Backing::Remote(r) = &h.backing else { panic!("not remote") };
    Arc::clone(&r.shared)
}

/// Serves faults on its own thread until Firecracker's end of the socket closes.
fn run(mut h: Handler) -> thread::JoinHandle<(Handler, Result<()>)> {
    thread::spawn(move || {
        let res = h.run(None);
        (h, res)
    })
}

fn wait_until(what: &str, done: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn recording() -> Recording {
    Recording { working_set: PathBuf::new(), pack: None, seen: HashSet::new(), order: Vec::new() }
}

#[test]
fn prefetch_serves_faults_before_finishing() {
    // a signal makes the kernel withdraw a blocked thread's fault. if the thread then stays off-CPU
    // until prefetch copies its page, the handler never sees a fault. but a handler that doesn't
    // check for faults during prefetch never takes one, so a single run that does is proof enough.
    for _ in 0..3 {
        match prefetch_takes_fault() {
            None | Some(true) => return,
            Some(false) => {}
        }
    }
    panic!("prefetch left the fault for after the working set in every attempt");
}

fn prefetch_takes_fault() -> Option<bool> {
    const PAGES: u64 = 4096;
    let (mut h, guest) = guest(&page_marks(PAGES), local)?;
    let ps = page_size();
    let offsets: Vec<u64> = (0..PAGES).map(|i| i * ps).collect();
    let set = guest.file("working-set", &working_set::encode(&offsets));

    // the vCPU faults on the last page prefetch gets to
    let reads = guest.read(&[PAGES - 1]);
    let mut fds = PollSet::default();
    let faults = fds.add(h.uffd.as_fd(), PollFlags::POLLIN);
    fds.wait(Duration::from_secs(5)).unwrap();
    assert!(fds.readable(faults), "the fault never arrived");
    drop(fds);

    h.prefetch(&set).unwrap();
    assert_eq!(reads.recv().unwrap(), (PAGES - 1, mark(PAGES - 1)));
    Some(h.stats.faults.get() > 0)
}

#[test]
fn remote_fetches_chunks_on_fault() {
    const HOLE: u64 = 3;
    const DATA_PAGES: u64 = 512;
    let ps = page_size();
    let mut mem = page_marks(REMOTE_PAGES);
    // one hole inside the first chunk, then nothing but holes from DATA_PAGES on
    mem[(HOLE * ps) as usize..((HOLE + 1) * ps) as usize].fill(0);
    mem[(DATA_PAGES * ps) as usize..].fill(0);
    let data = vec![0..HOLE * ps, (HOLE + 1) * ps..DATA_PAGES * ps];
    let srv = RangeServer::start(vec![("/mem", mem.clone())], vec![]);
    let url = format!("{}/mem", srv.url);

    let Some((mut h, guest)) = guest(&mem, remote(url, CHUNK_PAGES * ps, data)) else { return };
    // a signal can make a blocked thread fault twice, so count distinct pages, not faults
    h.recording = Some(recording());
    let shared = remote_shared(&h);
    let served = run(h);

    // the hole gets zeroed before its chunk shows up, so the chunk's copy skips it later
    for (page, value) in guest.read(&[HOLE, 5, 10, 700]) {
        let want = if page < DATA_PAGES && page != HOLE { mark(page) } else { 0 };
        assert_eq!(value, want, "page {page}");
    }

    // serve queues the rest behind the working set. here it follows the faults to stay deterministic
    shared.request_all();
    wait_until("the fill", || shared.pending() == 0);
    // everything's in, so the guest doesn't need the server anymore
    let gets = srv.gets("/mem");
    for (page, value) in guest.read(&[100, 511]) {
        assert_eq!(value, mark(page), "page {page}");
    }
    assert_eq!(srv.gets("/mem"), gets);

    drop(guest.peer);
    let (h, res) = served.join().unwrap();
    res.unwrap();
    assert_eq!(gets as u64, DATA_PAGES / CHUNK_PAGES, "one fetch per chunk with data, none for the holes");
    assert_eq!(h.recording.unwrap().order, [HOLE * ps, 5 * ps, 700 * ps], "pages 10, 100 and 511 came in with their chunks");
    assert_eq!(h.stats.copied_bytes.get(), (DATA_PAGES - 1) * ps, "every data page but the zeroed hole");
}

#[test]
fn remote_prefetch_queues_working_set() {
    let ps = page_size();
    let mem = page_marks(REMOTE_PAGES);
    let srv = RangeServer::start(vec![("/mem", mem.clone())], vec![]);
    let url = format!("{}/mem", srv.url);
    let Some((mut h, guest)) = guest(&mem, remote(url, CHUNK_PAGES * ps, whole(&mem))) else { return };
    let set = guest.file("working-set", &working_set::encode(&[0, ps, 40 * ps]));

    h.prefetch(&set).unwrap();
    let shared = remote_shared(&h);
    assert_eq!(shared.pending(), 2, "pages 0 and 1 share a chunk");
    shared.request_all();
    let served = run(h);

    assert_eq!(guest.read(&[40]).recv().unwrap(), (40, mark(40)));
    wait_until("the fill", || shared.pending() == 0);
    drop(guest.peer);
    served.join().unwrap().1.unwrap();
    assert_eq!(srv.gets("/mem") as u64, REMOTE_PAGES / CHUNK_PAGES, "each chunk once, working set first");
}

#[test]
fn remote_prefetch_reads_pack() {
    let ps = page_size();
    let mem = page_marks(REMOTE_PAGES);
    // scattered across many chunks, which is what the pack is for
    let offsets = [900 * ps, 17 * ps, 500 * ps, 3 * ps, 640 * ps];
    let pack: Vec<u8> = offsets.iter().flat_map(|&off| mem[off as usize..(off + ps) as usize].iter().copied()).collect();
    let srv = RangeServer::start(vec![("/mem", mem.clone()), ("/pack", pack)], vec![]);
    let url = format!("{}/mem", srv.url);
    // two pages per pack piece, so three pieces
    let pack_url = Some(format!("{}/pack", srv.url));
    let Some((mut h, guest)) = guest(&mem, remote_packed(url, pack_url, 2 * ps, whole(&mem))) else { return };
    let set = guest.file("working-set", &working_set::encode(&offsets));

    h.prefetch(&set).unwrap();
    let shared = remote_shared(&h);
    assert_eq!(shared.pending(), 3);
    let served = run(h);

    let pages: Vec<u64> = offsets.iter().map(|off| off / ps).collect();
    for (page, value) in guest.read(&pages) {
        assert_eq!(value, mark(page), "page {page}");
    }
    wait_until("the pack", || shared.pending() == 0);
    drop(guest.peer);
    served.join().unwrap().1.unwrap();
    assert_eq!(srv.gets("/pack"), 3);
    assert_eq!(srv.gets("/mem"), 0, "working-set pages came from the pack, not their chunks");
}

#[test]
fn remote_retries_a_failed_fill_chunk() {
    let ps = page_size();
    let mem = page_marks(REMOTE_PAGES);
    // the fill's single fetcher grabs chunk 0 first, and all of its own attempts at it fail
    let srv = RangeServer::start(vec![("/mem", mem.clone())], vec![503, 503, 503]);
    let url = format!("{}/mem", srv.url);
    let Some((h, guest)) = guest(&mem, remote(url, CHUNK_PAGES * ps, whole(&mem))) else { return };
    let shared = remote_shared(&h);
    shared.request_all();
    let served = run(h);

    wait_until("the fill", || shared.pending() == 0);
    assert_eq!(guest.read(&[0]).recv().unwrap(), (0, mark(0)));
    drop(guest.peer);
    let (h, res) = served.join().unwrap();
    res.unwrap();
    assert_eq!(h.stats.fetch_failures.get(), 1);
    assert_eq!(srv.gets("/mem") as u64, REMOTE_PAGES / CHUNK_PAGES, "chunk 0 came in on its retry");
}

#[test]
fn remote_leaves_a_refused_fill_chunk_to_a_fault() {
    let ps = page_size();
    let mem = page_marks(REMOTE_PAGES);
    // chunk 0 gets an expired URL's 403, then the URL works again like a fresh one would
    let srv = RangeServer::start(vec![("/mem", mem.clone())], vec![403]);
    let url = format!("{}/mem", srv.url);
    let Some((h, guest)) = guest(&mem, remote(url, CHUNK_PAGES * ps, whole(&mem))) else { return };
    let shared = remote_shared(&h);
    shared.request_all();
    let served = run(h);

    wait_until("the fill", || shared.pending() == 0);
    assert_eq!(shared.abandoned(), 1, "a refusal isn't retried in the background");
    assert_eq!(guest.read(&[3]).recv().unwrap(), (3, mark(3)), "a fault fetches it again");
    assert_eq!(shared.abandoned(), 0);
    drop(guest.peer);
    served.join().unwrap().1.unwrap();
}

#[test]
fn remote_fails_when_a_faults_fetch_fails() {
    let ps = page_size();
    let mem = page_marks(REMOTE_PAGES);
    let srv = RangeServer::start(vec![("/mem", mem.clone())], vec![503, 503, 503]);
    let url = format!("{}/mem", srv.url);
    let Some((h, guest)) = guest(&mem, remote(url, CHUNK_PAGES * ps, whole(&mem))) else { return };
    let served = run(h);

    let reads = guest.read(&[5]);
    let (h, res) = served.join().unwrap();
    assert!(res.is_err(), "the vCPU can't wait out a backoff");
    assert_eq!(h.stats.fetch_failures.get(), 1);
    // dropping the uffd lets the blocked read finish, so it's safe to unmap the region after
    drop(h);
    reads.recv_timeout(Duration::from_secs(5)).unwrap();
}

#[test]
fn record_writes_pack() {
    let ps = page_size();
    let Some((mut h, guest)) = guest(&page_marks(64), local) else { return };
    let (ws, pack) = (guest.dir.path().join("ws"), guest.dir.path().join("pack"));
    h.recording = Some(Recording { working_set: ws.clone(), pack: Some(pack.clone()), ..recording() });
    let served = run(h);

    let reads: Vec<_> = guest.read(&[40, 7]).iter().collect();
    assert_eq!(reads, [(40, mark(40)), (7, mark(7))]);
    drop(guest.peer);
    let (mut h, res) = served.join().unwrap();
    res.unwrap();
    h.finish_recording();
    h.join_publishing();

    assert_eq!(working_set::read(&ws).unwrap(), [40 * ps, 7 * ps]);
    let pack = fs::read(pack).unwrap();
    assert_eq!(pack.len() as u64, 2 * ps);
    assert_eq!([pack[0], pack[ps as usize]], [mark(40), mark(7)], "pages in recording order");
}

/// A uffd whose process already exited, like the one the handler holds between VMM exit and EOF.
/// `None` when this kernel or sandbox doesn't allow it.
fn orphaned_uffd(region: &MmapMut) -> Option<OwnedFd> {
    let (ready, ready_tx) = nix::unistd::pipe().unwrap();
    let (release_rx, release) = nix::unistd::pipe().unwrap();
    // the child can only make raw syscalls, so give it the bare fds
    let (child_ready, child_release) = (ready_tx.as_raw_fd(), release_rx.as_raw_fd());
    let register = [region.as_ptr() as u64, region.len() as u64, UFFDIO_REGISTER_MODE_MISSING, 0];
    // SAFETY: the child only makes raw syscalls on its own stack, so forking a threaded test is ok.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork: {}", Errno::last());
    if pid == 0 {
        // SAFETY: async-signal-safe syscalls on live args. the child never returns into the test.
        unsafe {
            let fd = libc::syscall(libc::SYS_userfaultfd, libc::c_long::from(libc::O_CLOEXEC | libc::O_NONBLOCK) | UFFD_USER_MODE_ONLY);
            let (mut api, mut register) = ([UFFD_API, 0, 0], register);
            let fd = if fd >= 0
                && libc::ioctl(fd as i32, UFFDIO_API, &raw mut api) == 0
                && libc::ioctl(fd as i32, UFFDIO_REGISTER, &raw mut register) == 0
            {
                fd as i32
            } else {
                -1
            };
            libc::write(child_ready, (&raw const fd).cast(), size_of::<i32>());
            libc::read(child_release, [0u8; 1].as_mut_ptr().cast(), 1);
            libc::_exit(0);
        }
    }
    let mut fd = [0; size_of::<i32>()];
    assert_eq!(nix::unistd::read(&ready, &mut fd).unwrap(), fd.len(), "child's fd");
    let fd = i32::from_ne_bytes(fd);
    let taken = (fd >= 0).then(|| {
        // SAFETY: pidfd_open and pidfd_getfd take plain integers and return a new descriptor or -1.
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(pidfd >= 0, "pidfd_open: {}", Errno::last());
        // SAFETY: as above.
        let uffd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd as i32, fd, 0) };
        // SAFETY: pidfd_open just gave us pidfd and nobody else owns it.
        drop(unsafe { OwnedFd::from_raw_fd(pidfd as i32) });
        if uffd < 0 {
            eprintln!("skipping: pidfd_getfd: {}", Errno::last());
            return None;
        }
        // SAFETY: pidfd_getfd just gave us this fd and nobody else owns it.
        Some(unsafe { OwnedFd::from_raw_fd(uffd as i32) })
    });
    nix::unistd::write(&release, &[0]).unwrap();
    let mut status = 0;
    // SAFETY: status is a live int for the call. once the child's reaped, its mm is gone.
    assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid, "waitpid");
    if fd < 0 {
        eprintln!("skipping: userfaultfd unavailable in the child");
    }
    taken.flatten()
}

#[test]
fn copies_after_the_vmm_exits_stop_quietly() {
    let mem = page_marks(4);
    let region = MmapMut::map_anon(mem.len()).unwrap();
    let Some(uffd) = orphaned_uffd(&region) else { return };
    let dir = tempfile::tempdir().unwrap();
    let (path, sock) = (dir.path().join("mem"), dir.path().join("uffd.sock"));
    fs::write(&path, &mem).unwrap();
    // populating copies before any fault, so the first copy is the one that finds the mm gone
    let opts = Options { socket: sock.clone(), mode: Mode::FaultAll, ..local(&path) };
    let serving = thread::spawn(move || serve(&opts));
    wait_until("the socket", || sock.exists());
    let vmm = UnixStream::connect(&sock).unwrap();
    let body =
        format!(r#"[{{"base_host_virt_addr":{},"size":{},"offset":0,"page_size":{}}}]"#, region.as_ptr() as u64, mem.len(), page_size());
    sendmsg::<()>(
        vmm.as_raw_fd(),
        &[IoSlice::new(body.as_bytes())],
        &[ControlMessage::ScmRights(&[uffd.as_raw_fd()])],
        MsgFlags::empty(),
        None,
    )
    .unwrap();

    serving.join().unwrap().expect("a vmm exiting mid-copy is a clean exit");
}

#[test]
fn accept_publishes_the_socket_only_once_it_listens() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("uffd.sock");
    let accepting = {
        let sock = sock.clone();
        thread::spawn(move || handshake::accept(&sock))
    };
    wait_until("the socket", || sock.exists());
    let _client = UnixStream::connect(&sock).expect("the path appears only once a connect can succeed");
    accepting.join().unwrap().unwrap();
    assert!(!sock.exists(), "the listener is gone once the vmm connects");
}
