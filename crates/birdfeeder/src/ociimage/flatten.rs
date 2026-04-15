//! Squashes an image's layers into one list of entries, following the OCI rules for whiteouts and opaque dirs.
//! Regular files' contents get spooled to a file.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    fs::File,
    io::{self, Read, Write},
    str::FromStr,
};

use anyhow::{Context as _, Result, anyhow, bail};
use tar::EntryType;

use super::archive_path::ArchivePath;

const WHITEOUT_PREFIX: &[u8] = b".wh.";
const OPAQUE_WHITEOUT: &[u8] = b".wh..wh..opq";
/// PAX records that just mirror header fields. the writer regenerates these.
const BASIC_KEYS: [&[u8]; 10] = [b"path", b"linkpath", b"size", b"uid", b"gid", b"uname", b"gname", b"mtime", b"atime", b"ctime"];

/// Seconds and nanoseconds since the epoch, nanoseconds always in `0..1e9`. It parses and prints as a PAX time:
/// decimal seconds, optionally signed, with at most nine fractional digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Mtime {
    pub secs: i64,
    pub nanos: u32,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid PAX time {0:?}")]
pub struct InvalidMtime(String);

impl FromStr for Mtime {
    type Err = InvalidMtime;

    fn from_str(v: &str) -> Result<Self, Self::Err> {
        let (secs, frac) = v.split_once('.').unwrap_or((v, ""));
        let secs: i64 = secs.parse().map_err(|_| InvalidMtime(v.to_owned()))?;
        if !frac.bytes().all(|b| b.is_ascii_digit()) {
            return Err(InvalidMtime(v.to_owned()));
        }
        // digits past nanoseconds are dropped, not rounded.
        let nanos = frac.bytes().chain(std::iter::repeat(b'0')).take(9).fold(0, |n, d| n * 10 + u32::from(d - b'0'));
        Ok(if v.starts_with('-') && nanos > 0 { Self { secs: secs - 1, nanos: 1_000_000_000 - nanos } } else { Self { secs, nanos } })
    }
}

impl fmt::Display for Mtime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.nanos == 0 {
            return write!(f, "{}", self.secs);
        }
        let (sign, secs, nanos) =
            if self.secs < 0 { ("-", -(self.secs + 1), 1_000_000_000 - self.nanos) } else { ("", self.secs, self.nanos) };
        write!(f, "{sign}{secs}.{}", format!("{nanos:09}").trim_end_matches('0'))
    }
}

/// One file of the flattened image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: ArchivePath,
    pub kind: Kind,
    pub meta: Meta,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// where the contents start in the spool, and how long they are.
    Regular {
        offset: u64,
        size: u64,
    },
    Dir,
    /// the target as the image has it.
    Symlink(Vec<u8>),
    Hardlink(ArchivePath),
    Char {
        major: u32,
        minor: u32,
    },
    Block {
        major: u32,
        minor: u32,
    },
    Fifo,
    /// a type the OCI rules don't cover. we pass it through and let mksquashfs decide.
    Other(EntryType),
}

impl Kind {
    pub fn entry_type(&self) -> EntryType {
        match self {
            Self::Regular { .. } => EntryType::Regular,
            Self::Dir => EntryType::Directory,
            Self::Symlink(_) => EntryType::Symlink,
            Self::Hardlink(_) => EntryType::Link,
            Self::Char { .. } => EntryType::Char,
            Self::Block { .. } => EntryType::Block,
            Self::Fifo => EntryType::Fifo,
            Self::Other(t) => *t,
        }
    }
}

/// What a header records about any kind of file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Meta {
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub mtime: Mtime,
    /// PAX records besides the basic ones, such as xattrs, sorted by key.
    pub pax: Vec<(Vec<u8>, Vec<u8>)>,
}

/// What a name set by an upper layer does to lower layers' files under it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decided {
    /// a directory, which merges with lower layers' directories of that name.
    Merges,
    /// a file or a whiteout, which hides them.
    Hides,
}

/// Flattens layers top first, the order in which upper layers' whiteouts hide lower layers' files.
pub struct Flattener {
    seen: HashMap<ArchivePath, Decided>,
    opaque: HashSet<ArchivePath>,
    entries: Vec<Entry>,
    /// kept hardlinks whose targets live in a lower layer, as indices into entries, keyed by target name.
    pending: HashMap<ArchivePath, Vec<usize>>,
    spool: File,
    spooled: u64,
    limit: u64,
}

/// What a name in the layer being applied refers to, as a hardlink made in that layer sees it.
#[derive(Clone)]
enum Target {
    /// the kept entry of that name.
    Kept(ArchivePath),
    /// an entry an upper layer replaced or removed, by its index in this layer's tar.
    Shadowed(usize),
    /// whatever lower layers have under that name.
    Lower(ArchivePath),
}

/// Hardlink bookkeeping for the layer being applied.
#[derive(Default)]
struct LayerLinks {
    here: HashMap<ArchivePath, Target>,
    /// shadowed entries whose contents kept hardlinks still need. maps tar index to the links' indices in entries.
    wanted: BTreeMap<usize, Vec<usize>>,
    lower: Vec<(ArchivePath, Vec<usize>)>,
}

/// An entry's kind as far as hardlink bookkeeping needs it, before a kept entry's contents are read.
enum Shape {
    Dir,
    Hardlink(ArchivePath),
    File(EntryType),
}

impl Flattener {
    pub fn new(spool: File, limit: u64) -> Self {
        Self { seen: HashMap::new(), opaque: HashSet::new(), entries: Vec::new(), pending: HashMap::new(), spool, spooled: 0, limit }
    }

    /// Applies the next layer down. `open` returns its uncompressed tar. It only gets called a second time when a
    /// hardlink we keep points at a file an upper layer replaced or removed, since the link still needs its contents.
    pub fn layer<R: Read>(&mut self, open: impl Fn() -> Result<R>) -> Result<()> {
        // opaque markers hide only lower layers, so they apply once this layer is done.
        let mut layer_opaque = Vec::new();
        let mut links = LayerLinks::default();
        let mut archive = tar::Archive::new(open()?);
        for (index, entry) in archive.entries().context("flatten layers")?.enumerate() {
            let mut entry = entry.context("flatten layers")?;
            let Some((kind, name)) = classify(&entry)? else { continue };
            let parent = name.parent().expect("classify skips the root");
            if name.file_name() == OPAQUE_WHITEOUT {
                layer_opaque.push(parent);
                continue;
            }
            let (key, tombstone) = match name.file_name().strip_prefix(WHITEOUT_PREFIX) {
                Some(removed) => (parent.join(removed).with_context(|| format!("whiteout {name} names no file in its directory"))?, true),
                None => (name, false),
            };
            let shadowed = (self.seen.contains_key(&key) && !tombstone) || self.hidden(&key);
            if !shadowed {
                let decided = if tombstone || kind != EntryType::Directory { Decided::Hides } else { Decided::Merges };
                self.seen.insert(key.clone(), decided);
            }
            if tombstone {
                self.dangling(|t| *t == key || key.contains(t))?;
                continue;
            }
            if kind != EntryType::Directory {
                self.dangling(|t| key.contains(t))?;
            }
            let shape = match kind {
                EntryType::Directory => Shape::Dir,
                EntryType::Link => Shape::Hardlink(hardlink_target(&entry, &key)?),
                k => Shape::File(k),
            };
            let target = match &shape {
                Shape::Dir => None,
                Shape::Hardlink(t) => Some(links.here.get(t).cloned().unwrap_or_else(|| Target::Lower(t.clone()))),
                Shape::File(_) if shadowed => Some(Target::Shadowed(index)),
                Shape::File(_) => Some(Target::Kept(key.clone())),
            };
            match &target {
                Some(t) => {
                    links.here.insert(key.clone(), t.clone());
                    if let Some(waiting) = self.pending.remove(&key) {
                        self.attach(&mut links, waiting, t.clone());
                    }
                }
                None => self.dangling(|t| *t == key)?,
            }
            if shadowed {
                continue;
            }
            let is_link = matches!(shape, Shape::Hardlink(_));
            let e = self.entry(&mut entry, shape, key)?;
            self.entries.push(e);
            if let (true, Some(t)) = (is_link, target) {
                self.attach(&mut links, vec![self.entries.len() - 1], t);
            }
        }
        if !links.wanted.is_empty() {
            self.recover(open()?, links.wanted)?;
        }
        for (t, waiting) in links.lower {
            self.pending.entry(t).or_default().extend(waiting);
        }
        for dir in &layer_opaque {
            self.dangling(|t| dir.contains(t))?;
        }
        self.opaque.extend(layer_opaque);
        Ok(())
    }

    /// Points kept hardlinks at what target refers to, now or once the entry holding it is read.
    fn attach(&mut self, links: &mut LayerLinks, waiting: Vec<usize>, target: Target) {
        match target {
            Target::Kept(name) => {
                for i in waiting {
                    self.entries[i].kind = Kind::Hardlink(name.clone());
                }
            }
            Target::Shadowed(index) => links.wanted.entry(index).or_default().extend(waiting),
            Target::Lower(name) => links.lower.push((name, waiting)),
        }
    }

    /// Rereads a layer to get the shadowed entries kept hardlinks need. The first link to each one becomes a copy
    /// (a link shares its target's inode), and the rest link to that copy.
    fn recover(&mut self, layer: impl Read, mut wanted: BTreeMap<usize, Vec<usize>>) -> Result<()> {
        let mut archive = tar::Archive::new(layer);
        for (index, entry) in archive.entries().context("reread layer")?.enumerate() {
            let Some(waiting) = wanted.remove(&index) else { continue };
            let mut entry = entry.context("reread layer")?;
            let (kind, _) = classify(&entry)?.expect("the first read of this layer found a file here");
            // only files a hardlink can target are shadowed, never directories or other hardlinks.
            let copy = self.entry(&mut entry, Shape::File(kind), self.entries[waiting[0]].name.clone())?;
            for &i in &waiting[1..] {
                self.entries[i].kind = Kind::Hardlink(copy.name.clone());
            }
            self.entries[waiting[0]] = copy;
            if wanted.is_empty() {
                break;
            }
        }
        Ok(())
    }

    /// Fails when a file a kept hardlink targets is gone by the time the link's layer applies.
    fn dangling(&self, gone: impl Fn(&ArchivePath) -> bool) -> Result<()> {
        if let Some((target, waiting)) = self.pending.iter().find(|(t, _)| gone(t)) {
            bail!("hardlink {} targets {target}, which isn't in the image", self.entries[waiting[0]].name);
        }
        Ok(())
    }

    /// Whether an upper layer removed a parent of name, or made one opaque.
    fn hidden(&self, name: &ArchivePath) -> bool {
        name.ancestors().any(|dir| self.seen.get(&dir) == Some(&Decided::Hides) || self.opaque.contains(&dir))
    }

    /// Normalizes a kept entry and spools a regular file's contents.
    fn entry<R: Read>(&mut self, entry: &mut tar::Entry<'_, R>, shape: Shape, name: ArchivePath) -> Result<Entry> {
        let meta = meta(entry, &name)?;
        let header = entry.header();
        // a v7 header has no device fields, so they read as 0.
        let device = match (header.device_major(), header.device_minor()) {
            (Ok(Some(major)), Ok(Some(minor))) => (major, minor),
            _ => (0, 0),
        };
        let kind = match shape {
            Shape::Dir => Kind::Dir,
            Shape::Hardlink(target) => Kind::Hardlink(target),
            Shape::File(EntryType::Regular) => {
                let offset = self.spooled;
                let size = io::copy(&mut entry.by_ref().take(self.limit - self.spooled + 1), &mut self.spool)
                    .with_context(|| format!("spool {name}"))?;
                self.spooled += size;
                if self.spooled > self.limit {
                    bail!("image exceeds {} bytes", self.limit);
                }
                Kind::Regular { offset, size }
            }
            Shape::File(EntryType::Symlink) => Kind::Symlink(entry.link_name_bytes().unwrap_or_default().into_owned()),
            Shape::File(EntryType::Char) => Kind::Char { major: device.0, minor: device.1 },
            Shape::File(EntryType::Block) => Kind::Block { major: device.0, minor: device.1 },
            Shape::File(EntryType::Fifo) => Kind::Fifo,
            Shape::File(other) => Kind::Other(other),
        };
        Ok(Entry { name, kind, meta })
    }

    /// The flattened image: parents before their children, hardlinks after their targets, and the spool.
    pub fn finish(mut self) -> Result<(Vec<Entry>, File)> {
        self.dangling(|_| true)?;
        self.spool.flush().context("spool")?;
        // layers apply top first, so a dir can land after its contents and a hardlink before its target. a
        // parent's name is a prefix of its children's, so it sorts first.
        let is_link = |e: &Entry| matches!(e.kind, Kind::Hardlink(_));
        self.entries.sort_by(|a, b| is_link(a).cmp(&is_link(b)).then_with(|| a.name.cmp(&b.name)));
        Ok((self.entries, self.spool))
    }
}

fn meta<R: Read>(entry: &mut tar::Entry<'_, R>, name: &ArchivePath) -> Result<Meta> {
    let header = entry.header();
    let mut mtime = Mtime { secs: header.mtime().context("read mtime")?.cast_signed(), nanos: 0 };
    let mode = header.mode().context("read mode")?;
    let (uid, gid) = (header.uid().context("read uid")?, header.gid().context("read gid")?);
    // the last record for a key wins, and the writer sorts them.
    let mut pax = BTreeMap::new();
    if let Some(records) = entry.pax_extensions().context("read PAX records")? {
        for r in records {
            let r = r.context("read PAX records")?;
            if r.key_bytes() == b"mtime" {
                mtime = r.value().context("read PAX mtime")?.parse().context("read PAX mtime")?;
            } else if r.key_bytes().starts_with(b"GNU.sparse.") {
                // unlike GNU sparse headers, the tar crate leaves PAX sparse maps for its caller to apply.
                bail!("PAX sparse file {name} isn't supported");
            } else if !BASIC_KEYS.contains(&r.key_bytes()) {
                pax.insert(r.key_bytes().to_vec(), r.value_bytes().to_vec());
            }
        }
    }
    Ok(Meta { mode, uid, gid, mtime, pax: pax.into_iter().collect() })
}

/// An entry's kind and its name, or None for entries that carry no file: PAX globals and the root itself, which the
/// bundle supplies.
fn classify<R: Read>(entry: &tar::Entry<'_, R>) -> Result<Option<(EntryType, ArchivePath)>> {
    let kind = entry.header().entry_type();
    if kind.is_pax_global_extensions() {
        return Ok(None);
    }
    let raw = entry.path_bytes();
    let name = ArchivePath::parse(&raw).map_err(|e| anyhow!("unsafe tar path {e}"))?;
    let kind = match kind {
        // before POSIX, a trailing slash marked a directory under the regular-file flag.
        EntryType::Regular if entry.header().as_bytes()[156] == 0 && raw.ends_with(b"/") => EntryType::Directory,
        // the tar crate fills a GNU sparse file's holes as it reads it.
        EntryType::Continuous | EntryType::GNUSparse => EntryType::Regular,
        k => k,
    };
    Ok((!name.is_root()).then_some((kind, name)))
}

/// A hardlink's target. It names another entry in the archive, not a path relative to the link.
fn hardlink_target<R: Read>(entry: &tar::Entry<'_, R>, name: &ArchivePath) -> Result<ArchivePath> {
    let raw = entry.link_name_bytes().unwrap_or_default();
    let target = ArchivePath::parse(&raw).map_err(|e| anyhow!("hardlink {name} targets {e}, outside the image"))?;
    if target.is_root() {
        bail!("hardlink {name} has no target");
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::nanoseconds("1700000001.123456789", 1_700_000_001, 123_456_789)]
    #[case::short_fraction("5.5", 5, 500_000_000)]
    #[case::past_nanoseconds("5.1234567891", 5, 123_456_789)]
    #[case::negative("-1.5", -2, 500_000_000)]
    #[case::whole("5", 5, 0)]
    fn parses_pax_times(#[case] text: &str, #[case] secs: i64, #[case] nanos: u32) {
        assert_eq!(text.parse::<Mtime>().unwrap(), Mtime { secs, nanos });
    }

    #[rstest]
    #[case::fraction_not_digits("1.x")]
    #[case::seconds_not_digits("x.5")]
    fn refuses_invalid_pax_times(#[case] text: &str) {
        assert!(text.parse::<Mtime>().is_err());
    }

    #[rstest]
    #[case::whole(5, 0, "5")]
    #[case::nanoseconds(1_700_000_001, 123_456_789, "1700000001.123456789")]
    #[case::trailing_zeros_trimmed(5, 500_000_000, "5.5")]
    #[case::negative(-2, 500_000_000, "-1.5")]
    fn formats_pax_times(#[case] secs: i64, #[case] nanos: u32, #[case] want: &str) {
        let t = Mtime { secs, nanos };
        assert_eq!(t.to_string(), want);
        assert_eq!(want.parse::<Mtime>().unwrap(), t, "round trip");
    }
}
