//! Writes the flattened image as a tar of an OCI bundle, config.json and rootfs/, for mksquashfs to pack.

use std::{
    fs::File,
    io::{self, Read, Write},
    os::unix::fs::FileExt as _,
    sync::atomic::{AtomicBool, Ordering},
};

use anyhow::{Context as _, Result, bail};
use tar::Header;

use super::{
    flatten::{Entry, Kind, Meta},
    spec::{self, ImageConfig},
};

/// user lookups read at most this much of /etc/passwd or /etc/group.
const MAX_ACCOUNT_DB: u64 = 1 << 20;
const CONFIG_MODE: u32 = 0o644;
const ROOTFS_MODE: u32 = 0o755;
/// the biggest values a ustar header's octal fields can hold. anything bigger goes in a PAX record.
const MAX_OCTAL_ID: u64 = 0o7_777_777;
const MAX_OCTAL_SIZE: u64 = 0o77_777_777_777;
const NAME_LEN: usize = 100;

/// Writes the bundle of a flattened image to w. Setting `cancelled` stops a long write between entries.
pub fn write(cfg: &ImageConfig, entries: &[Entry], spool: &File, w: impl Write, cancelled: &AtomicBool) -> Result<()> {
    let config = config_json(cfg, entries, spool)?;
    let mut tw = tar::Builder::new(w);
    let root_owned = |mode| Meta { mode, ..Meta::default() };
    let config_kind = Kind::Regular { offset: 0, size: config.len() as u64 };
    append(&mut tw, b"config.json", &config_kind, None, &root_owned(CONFIG_MODE), &config[..])?;
    append(&mut tw, b"rootfs", &Kind::Dir, None, &root_owned(ROOTFS_MODE), io::empty())?;
    for e in entries {
        if cancelled.load(Ordering::Relaxed) {
            bail!("cancelled");
        }
        let name = [b"rootfs/", e.name.as_bytes()].concat();
        let link = match &e.kind {
            Kind::Symlink(target) => Some(target.clone()),
            Kind::Hardlink(target) => Some([b"rootfs/", target.as_bytes()].concat()),
            _ => None,
        };
        let (offset, left) = match e.kind {
            Kind::Regular { offset, size } => (offset, size),
            _ => (0, 0),
        };
        append(&mut tw, &name, &e.kind, link.as_deref(), &e.meta, Section { file: spool, offset, left })?;
    }
    tw.into_inner().context("finish bundle")?.flush().context("finish bundle")?;
    Ok(())
}

fn config_json(cfg: &ImageConfig, entries: &[Entry], spool: &File) -> Result<Vec<u8>> {
    // an image that runs as root doesn't need an account lookup, so weird passwd/group files can't block it.
    let (passwd, group) = if cfg.user.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        (read_file(entries, spool, b"etc/passwd")?, read_file(entries, spool, b"etc/group")?)
    };
    Ok(spec::encode(&spec::image_spec(cfg, &passwd, &group)?))
}

/// A regular file's contents from the flattened image, or nothing when it's absent.
fn read_file(entries: &[Entry], spool: &File, name: &[u8]) -> Result<Vec<u8>> {
    let shown = String::from_utf8_lossy(name);
    let Some(e) = entries.iter().find(|e| e.name.as_bytes() == name) else { return Ok(Vec::new()) };
    let Kind::Regular { offset, size } = e.kind else { bail!("/{shown} isn't a regular file") };
    if size > MAX_ACCOUNT_DB {
        bail!("/{shown} exceeds {MAX_ACCOUNT_DB} bytes");
    }
    let mut data = vec![0; size as usize];
    spool.read_exact_at(&mut data, offset).with_context(|| format!("read /{shown}"))?;
    Ok(data)
}

fn append<W: Write>(tw: &mut tar::Builder<W>, name: &[u8], kind: &Kind, link: Option<&[u8]>, meta: &Meta, body: impl Read) -> Result<()> {
    let shown = String::from_utf8_lossy(name);
    let mut pax: Vec<(&[u8], Vec<u8>)> = meta.pax.iter().map(|(k, v)| (&k[..], v.clone())).collect();
    let mut h = Header::new_ustar();
    h.set_entry_type(kind.entry_type());
    if needs_pax(name) {
        pax.push((b"path", name.to_vec()));
    }
    set_field(&mut h.as_old_mut().name, name);
    if let Some(link) = link {
        if needs_pax(link) {
            pax.push((b"linkpath", link.to_vec()));
        }
        set_field(&mut h.as_old_mut().linkname, link);
    }
    h.set_mode(meta.mode);
    for (key, id, set) in [(&b"uid"[..], meta.uid, Header::set_uid as fn(&mut Header, u64)), (b"gid", meta.gid, Header::set_gid)] {
        if id > MAX_OCTAL_ID {
            pax.push((key, id.to_string().into_bytes()));
        }
        set(&mut h, id.min(MAX_OCTAL_ID));
    }
    let size = match kind {
        Kind::Regular { size, .. } => *size,
        _ => 0,
    };
    if size > MAX_OCTAL_SIZE {
        pax.push((b"size", size.to_string().into_bytes()));
    }
    h.set_size(size);
    // a sub-second or out-of-range mtime only fits in a PAX record. the header just gets whole seconds.
    let mtime = meta.mtime;
    if mtime.nanos != 0 || !(0..=MAX_OCTAL_SIZE.cast_signed()).contains(&mtime.secs) {
        pax.push((b"mtime", mtime.to_string().into_bytes()));
    }
    h.set_mtime(mtime.secs.clamp(0, MAX_OCTAL_SIZE.cast_signed()).cast_unsigned());
    if let Kind::Char { major, minor } | Kind::Block { major, minor } = *kind {
        h.set_device_major(major).context("set device")?;
        h.set_device_minor(minor).context("set device")?;
    }
    if !pax.is_empty() {
        pax.sort();
        let records = pax.iter().map(|(k, v)| std::str::from_utf8(k).map(|k| (k, &v[..])));
        let records: Vec<_> = records.collect::<Result<_, _>>().with_context(|| format!("write {shown}: PAX key isn't UTF-8"))?;
        tw.append_pax_extensions(records).with_context(|| format!("write {shown}"))?;
    }
    h.set_cksum();
    tw.append(&h, body).with_context(|| format!("write {shown}"))
}

/// A name too long for the header, or not ASCII, goes in a PAX record.
fn needs_pax(s: &[u8]) -> bool {
    s.len() > NAME_LEN || !s.is_ascii()
}

fn set_field(field: &mut [u8; NAME_LEN], s: &[u8]) {
    let n = s.len().min(NAME_LEN);
    field[..n].copy_from_slice(&s[..n]);
}

/// Reads a span of the spool without moving a shared cursor.
struct Section<'a> {
    file: &'a File,
    offset: u64,
    left: u64,
}

impl Read for Section<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let want = buf.len().min(usize::try_from(self.left).unwrap_or(usize::MAX));
        if want == 0 {
            return Ok(0);
        }
        let n = self.file.read_at(&mut buf[..want], self.offset)?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.offset += n as u64;
        self.left -= n as u64;
        Ok(n)
    }
}
