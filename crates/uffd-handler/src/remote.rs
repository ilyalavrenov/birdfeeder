//! A memory file behind a range server. A round trip takes milliseconds, so we fetch a chunk at a
//! time and copy each chunk straight into the guest. The guest's own memory is the cache, and this
//! process never keeps a second copy.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use std::fmt;
use std::mem;
use std::num::{NonZeroU64, NonZeroUsize};
use std::ops::Range;
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use memmap2::MmapMut;
use nix::sys::eventfd::{EfdFlags, EventFd};

use crate::extents::Extents;
use crate::fetch::RangeFetcher;
use crate::layout::PageSize;
use crate::stats::Stats;

pub const DEFAULT_CHUNK: NonZeroU64 = NonZeroU64::new(1 << 20).unwrap();
pub const DEFAULT_FETCHERS: NonZeroUsize = NonZeroUsize::new(8).unwrap();
/// The fill fights the booting guest for CPU. On a 2-vCPU host 8 fillers added about 85 ms to a
/// prefetching restore's ready time, so use one and just finish later.
const FILL_FETCHERS: usize = 1;
/// How many times a failed fetch nobody's waiting on gets requeued, doubling the wait each time.
/// That rides out about half a minute of S3 brownout. After that only a fault fetches it.
const BACKGROUND_RETRIES: u32 = 5;
const RETRY_BACKOFF: Duration = Duration::from_secs(1);

/// What one fetch reads: a chunk of the memory file, or a piece of the packed working set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FetchId {
    Chunk(u64),
    Piece(u64),
}

impl fmt::Display for FetchId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chunk(c) => write!(f, "chunk {c}"),
            Self::Piece(p) => write!(f, "pack piece {p}"),
        }
    }
}

/// How soon a fetch is wanted, most urgent first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    /// a vCPU is (or will be) waiting on it: a fault's fetch, or everything when populating.
    Urgent,
    /// the working set, plus fetches retrying after a failure.
    Background,
    /// the rest of the file, which only [`FILL_FETCHERS`] of the fetchers take.
    Fill,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Queued,
    Fetching,
    Done,
    /// failed too many times with no fault waiting. a fault on it queues it again.
    Abandoned,
}

/// A finished fetch. The buffer is page-aligned, as `UFFDIO_COPY` wants its source.
pub struct Fetched {
    pub id: FetchId,
    /// [`Priority::Urgent`] when a fault was already waiting on it as the fetch began.
    pub priority: Priority,
    pub buf: Result<MmapMut>,
}

/// What [`Shared::failed`] did with a failed fetch.
#[derive(Debug, PartialEq, Eq)]
pub enum Retry {
    /// a fault was waiting on it, and the fetcher's own retries didn't get it.
    Fatal,
    Later(Duration),
    Abandoned,
}

#[derive(Default)]
struct Queue {
    // a fault's fetch jumps ahead of the queued working set. each fetch is taken once, from
    // whichever list gets to it first.
    urgent: VecDeque<FetchId>,
    background: VecDeque<FetchId>,
    fill: VecDeque<FetchId>,
    state: HashMap<FetchId, State>,
    /// what faults have asked for and haven't gotten yet.
    awaited: HashSet<FetchId>,
    failures: HashMap<FetchId, u32>,
    /// failed fetches waiting out their backoff, soonest first.
    retries: BinaryHeap<Reverse<(Instant, FetchId)>>,
    // counts of `state` by kind, kept in sync by [`Queue::set_state`]. the handler asks after every
    // batch of fetches, way too often to count every chunk in the file each time.
    outstanding: usize,
    abandoned: usize,
    /// whether nothing was outstanding once already. that's when the guest stops needing the URL.
    loaded: bool,
    finished: Vec<Fetched>,
    closed: bool,
}

impl Queue {
    fn list(&mut self, p: Priority) -> &mut VecDeque<FetchId> {
        match p {
            Priority::Urgent => &mut self.urgent,
            Priority::Background => &mut self.background,
            Priority::Fill => &mut self.fill,
        }
    }

    /// The next fetch queued at `lowest` or more urgently, and the priority it was queued at.
    fn pop(&mut self, lowest: Priority) -> Option<(FetchId, Priority)> {
        [Priority::Urgent, Priority::Background, Priority::Fill]
            .into_iter()
            .take_while(|&p| p <= lowest)
            .find_map(|p| self.list(p).pop_front().map(|id| (id, p)))
    }

    /// The count `state` is part of.
    fn count(&mut self, state: State) -> Option<&mut usize> {
        match state {
            State::Queued | State::Fetching => Some(&mut self.outstanding),
            State::Abandoned => Some(&mut self.abandoned),
            State::Done => None,
        }
    }

    fn set_state(&mut self, id: FetchId, state: State) -> Option<State> {
        let old = self.state.insert(id, state);
        if let Some(n) = old.and_then(|s| self.count(s)) {
            *n -= 1;
        }
        if let Some(n) = self.count(state) {
            *n += 1;
        }
        old
    }

    /// Moves retries done backing off onto the background list, and says when the next one's due.
    fn release_due(&mut self, now: Instant) -> Option<Instant> {
        while let Some(&Reverse((at, id))) = self.retries.peek() {
            if at > now {
                return Some(at);
            }
            self.retries.pop();
            self.background.push_back(id);
        }
        None
    }
}

/// The working set's pages packed into one object in first-touch order, so prefetch grabs just
/// those pages and not every chunk they land in.
struct Pack {
    fetcher: RangeFetcher,
    pages: Vec<u64>,
    pages_per_piece: u64,
    page_size: PageSize,
}

/// What the handler and the fetcher threads share.
pub struct Shared {
    pub size: u64,
    pub chunk: u64,
    pub data: Extents,
    pub started: Instant,
    mem: RangeFetcher,
    pack: OnceLock<Pack>,
    queue: Mutex<Queue>,
    more: Condvar,
    /// the poll loop watches this. fetchers bump it when a fetch finishes.
    wake: EventFd,
    stats: Arc<Stats>,
}

impl Shared {
    fn queue(&self) -> MutexGuard<'_, Queue> {
        self.queue.lock().expect("a fetcher panicked holding the queue")
    }

    pub fn chunks(&self) -> u64 {
        self.size.div_ceil(self.chunk)
    }

    pub fn chunk_range(&self, c: u64) -> Range<u64> {
        c * self.chunk..((c + 1) * self.chunk).min(self.size)
    }

    /// Queues chunk `c` unless it's already on its way or holds no data.
    pub fn request(&self, c: u64, priority: Priority) {
        if self.data.overlaps(self.chunk_range(c)) {
            self.enqueue(FetchId::Chunk(c), priority);
        }
    }

    fn enqueue(&self, id: FetchId, priority: Priority) {
        let mut q = self.queue();
        let state = q.state.get(&id).copied();
        if state == Some(State::Done) {
            return;
        }
        let urgent = priority == Priority::Urgent;
        if urgent {
            q.awaited.insert(id);
        }
        match state {
            None | Some(State::Abandoned) => {
                q.set_state(id, State::Queued);
            }
            Some(State::Queued) if urgent => {}
            Some(_) => return,
        }
        q.list(priority).push_back(id);
        self.more.notify_one();
    }

    /// Queues every chunk with data for the fill.
    pub fn request_all(&self) {
        let mut q = self.queue();
        for c in 0..self.chunks() {
            let id = FetchId::Chunk(c);
            if !q.state.contains_key(&id) && self.data.overlaps(self.chunk_range(c)) {
                q.set_state(id, State::Queued);
                q.fill.push_back(id);
            }
        }
        self.more.notify_all();
    }

    pub fn pending(&self) -> usize {
        self.queue().outstanding
    }

    /// Fetches the background gave up on. Only a fault will fetch these now.
    pub fn abandoned(&self) -> usize {
        self.queue().abandoned
    }

    /// True once: the first time nothing is left to fetch.
    pub fn just_loaded(&self) -> bool {
        let mut q = self.queue();
        let loaded = !q.loaded && q.outstanding == 0;
        q.loaded |= loaded;
        loaded
    }

    pub fn mark_done(&self, id: FetchId) {
        let mut q = self.queue();
        q.set_state(id, State::Done);
        q.awaited.remove(&id);
    }

    /// Decides what happens after a failed fetch of `id`. It's only fatal if a fault was already
    /// waiting when the fetch began: the fetcher already retried, and the vCPU can't sit through a
    /// backoff. Anything else goes again, right away if a fault asked for it since, otherwise after
    /// a backoff. We give up after [`BACKGROUND_RETRIES`] or a refusal.
    pub fn failed(&self, id: FetchId, priority: Priority, refused: bool) -> Retry {
        if priority == Priority::Urgent {
            return Retry::Fatal;
        }
        let mut q = self.queue();
        q.set_state(id, State::Queued);
        if q.awaited.contains(&id) {
            q.urgent.push_back(id);
            self.more.notify_one();
            return Retry::Later(Duration::ZERO);
        }
        let failures = q.failures.entry(id).or_default();
        *failures += 1;
        let failures = *failures;
        if refused || failures > BACKGROUND_RETRIES {
            q.set_state(id, State::Abandoned);
            return Retry::Abandoned;
        }
        let delay = RETRY_BACKOFF * 2u32.pow(failures - 1);
        q.retries.push(Reverse((Instant::now() + delay, id)));
        // a fetcher sleeping until a later deadline (or with none) has to look again
        self.more.notify_all();
        Retry::Later(delay)
    }

    fn is_done(&self, id: FetchId) -> bool {
        self.queue().state.get(&id) == Some(&State::Done)
    }

    pub fn wake_fd(&self) -> BorrowedFd<'_> {
        self.wake.as_fd()
    }

    pub fn take_finished(&self) -> Vec<Fetched> {
        // EAGAIN just means nothing new. `finished` is the source of truth
        let _ = self.wake.read();
        mem::take(&mut self.queue().finished)
    }

    /// The byte range of pack piece `p`, and the working-set pages it holds.
    pub fn pack_piece(&self, p: u64) -> (Range<u64>, &[u64]) {
        let pack = self.pack.get().expect("pack pieces are queued only once the pack is set");
        let first = usize::try_from(p * pack.pages_per_piece).expect("pieces index a vec");
        let per = usize::try_from(pack.pages_per_piece).expect("pages per piece fit in usize");
        let pages = &pack.pages[first..(first + per).min(pack.pages.len())];
        let ps = pack.page_size.get();
        (first as u64 * ps..(first + pages.len()) as u64 * ps, pages)
    }

    /// Where `id` is read from, and its byte range there.
    fn source(&self, id: FetchId) -> (&RangeFetcher, Range<u64>) {
        match id {
            FetchId::Chunk(c) => (&self.mem, self.chunk_range(c)),
            FetchId::Piece(p) => (&self.pack.get().expect("set before its pieces are queued").fetcher, self.pack_piece(p).0),
        }
    }

    /// The next fetch queued at `lowest` or more urgently, and its priority now.
    fn next(&self, lowest: Priority) -> Option<(FetchId, Priority)> {
        let mut q = self.queue();
        loop {
            let retry_at = q.release_due(Instant::now());
            while let Some((id, queued)) = q.pop(lowest) {
                if q.state.get(&id) == Some(&State::Queued) {
                    q.set_state(id, State::Fetching);
                    let priority = if q.awaited.contains(&id) { Priority::Urgent } else { queued };
                    return Some((id, priority));
                }
            }
            if q.closed {
                return None;
            }
            q = match retry_at {
                Some(at) => {
                    self.more.wait_timeout(q, at.saturating_duration_since(Instant::now())).expect("a fetcher panicked holding the queue").0
                }
                None => self.more.wait(q).expect("a fetcher panicked holding the queue"),
            };
        }
    }

    /// Fetches what's queued at `lowest` or more urgently until the handler goes away.
    fn work(&self, lowest: Priority) {
        while let Some((id, priority)) = self.next(lowest) {
            let (from, range) = self.source(id);
            let len = range.end - range.start;
            let buf =
                MmapMut::map_anon(usize::try_from(len).expect("chunks fit in memory")).context("mmap chunk buffer").and_then(|mut buf| {
                    from.fetch(range.start, &mut buf)?;
                    Ok(buf)
                });
            if buf.is_ok() {
                self.stats.fetches.add(1);
                self.stats.fetched_bytes.add(len);
            }
            self.queue().finished.push(Fetched { id, priority, buf });
            // this only fails on a full counter, and that already wakes the loop
            let _ = self.wake.write(1);
        }
    }
}

/// The handler's side of a remote memory file. Dropping it stops the fetchers once their current
/// fetch ends. The process exits soon after, so nothing waits on them.
pub struct Remote {
    pub shared: Arc<Shared>,
    pack_url: Option<String>,
    /// maps a working-set page's offset to the pack piece holding it.
    pack_index: HashMap<u64, u64>,
}

impl Remote {
    /// Starts `fetchers` threads over the memory file at `url`; `chunk` must be a multiple of the
    /// guest page size.
    pub fn start(
        url: &str,
        pack_url: Option<String>,
        size: u64,
        data: Extents,
        chunk: u64,
        fetchers: NonZeroUsize,
        stats: Arc<Stats>,
    ) -> Result<Self> {
        let wake = EventFd::from_flags(EfdFlags::EFD_CLOEXEC | EfdFlags::EFD_NONBLOCK).context("eventfd")?;
        let shared = Arc::new(Shared {
            size,
            chunk,
            data,
            started: Instant::now(),
            mem: RangeFetcher::new(url),
            pack: OnceLock::new(),
            queue: Mutex::default(),
            more: Condvar::new(),
            wake,
            stats,
        });
        for i in 0..fetchers.get() {
            let shared = Arc::clone(&shared);
            let lowest = if i < FILL_FETCHERS { Priority::Fill } else { Priority::Background };
            thread::Builder::new().name(format!("fetcher-{i}")).spawn(move || shared.work(lowest)).context("start fetcher")?;
        }
        Ok(Self { shared, pack_url, pack_index: HashMap::new() })
    }

    pub fn has_pack(&self) -> bool {
        self.pack_url.is_some()
    }

    /// Queues the working set at `offsets` in the background: the pack's pieces when there's a
    /// pack, else the chunks those pages fall in.
    pub fn queue_working_set(&mut self, offsets: &[u64], page_size: PageSize) {
        let Some(url) = &self.pack_url else {
            for &off in offsets {
                self.shared.request(off / self.shared.chunk, Priority::Background);
            }
            return;
        };
        let pages_per_piece = self.shared.chunk / page_size.get();
        self.pack_index = offsets.iter().enumerate().map(|(i, &off)| (off, i as u64 / pages_per_piece)).collect();
        let pack = Pack { fetcher: RangeFetcher::new(url), pages: offsets.to_vec(), pages_per_piece, page_size };
        assert!(self.shared.pack.set(pack).is_ok(), "prefetch sets the pack once");
        for p in 0..(offsets.len() as u64).div_ceil(pages_per_piece) {
            self.shared.enqueue(FetchId::Piece(p), Priority::Background);
        }
    }

    /// Queues what holds the page at `off`: its piece of the pack if it's in the working set, else
    /// its chunk. A fault on a page that's already in is stale, since the copy woke its vCPU.
    pub fn fault(&self, off: u64) {
        if let Some(&p) = self.pack_index.get(&off) {
            let id = FetchId::Piece(p);
            if !self.shared.is_done(id) {
                self.shared.enqueue(id, Priority::Urgent);
            }
            return;
        }
        self.shared.request(off / self.shared.chunk, Priority::Urgent);
    }
}

impl Drop for Remote {
    fn drop(&mut self) {
        self.shared.queue().closed = true;
        self.shared.more.notify_all();
    }
}
