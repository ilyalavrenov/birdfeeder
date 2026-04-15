use std::{
    io::{Cursor, Read as _, Write as _},
    sync::atomic::AtomicBool,
};

use rstest::rstest;

use super::{
    bundle, check_bundle, decompress,
    flatten::{Entry, Flattener, Kind},
    spec::{ConfigFile, ImageConfig},
};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

/// What mksquashfs reads from a bundle entry: two bundles with equal listings pack to the same blob.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Listed {
    name: String,
    kind: u8,
    mode: u32,
    uid: u64,
    gid: u64,
    mtime: String,
    link: Option<String>,
    device: Option<(u32, u32)>,
    pax: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

fn list(bundle: &[u8]) -> Vec<Listed> {
    let mut archive = tar::Archive::new(bundle);
    let mut out = Vec::new();
    for e in archive.entries().unwrap() {
        let mut e = e.unwrap();
        let h = e.header().clone();
        let mut mtime = h.mtime().unwrap().to_string();
        let mut pax = Vec::new();
        for r in e.pax_extensions().unwrap().into_iter().flatten() {
            let r = r.unwrap();
            match r.key().unwrap() {
                "mtime" => mtime = r.value().unwrap().to_owned(),
                "path" | "linkpath" | "uid" | "gid" | "size" => {}
                k => pax.push((k.to_owned(), r.value_bytes().to_vec())),
            }
        }
        let device = matches!(h.entry_type(), tar::EntryType::Char | tar::EntryType::Block)
            .then(|| (h.device_major().unwrap().unwrap(), h.device_minor().unwrap().unwrap()));
        let mut body = Vec::new();
        e.read_to_end(&mut body).unwrap();
        out.push(Listed {
            name: String::from_utf8(e.path_bytes().into_owned()).unwrap(),
            kind: h.entry_type().as_byte(),
            mode: h.mode().unwrap(),
            uid: h.uid().unwrap(),
            gid: h.gid().unwrap(),
            mtime,
            link: e.link_name_bytes().map(|l| String::from_utf8(l.into_owned()).unwrap()),
            device,
            pax,
            body,
        });
    }
    out
}

fn spool() -> std::fs::File {
    tempfile::tempfile().unwrap()
}

/// Flattens layers given bottom first, as a manifest lists them.
fn flatten(layers: &[Vec<u8>]) -> anyhow::Result<(Vec<Entry>, std::fs::File)> {
    let mut flat = Flattener::new(spool(), u64::MAX / 2);
    for layer in layers.iter().rev() {
        flat.layer(|| Ok(&layer[..]))?;
    }
    flat.finish()
}

/// Flattens layers given bottom first and writes their bundle.
fn bundle_of(cfg: &ImageConfig, layers: &[Vec<u8>]) -> anyhow::Result<Vec<u8>> {
    let (entries, spool) = flatten(layers)?;
    let mut out = Vec::new();
    bundle::write(cfg, &entries, &spool, &mut out, &AtomicBool::new(false))?;
    Ok(out)
}

/// bundle.tar is what layer0.tar and layer1.tar should turn into. They cover whiteouts, an opaque dir, an escaping
/// symlink, long and non-ASCII names, xattrs, a sub-second mtime, big IDs, devices and hardlinks. The fixture's
/// config.json escapes HTML characters, so we compare it as JSON. It's also missing the escaping symlink, which we
/// keep because the kernel resolves it inside the container's root.
#[test]
fn bundle_matches_fixture() {
    let read = |name: &str| std::fs::read(format!("{FIXTURES}/{name}")).unwrap();
    let cfg: ConfigFile = serde_json::from_slice(&read("image-config.json")).unwrap();
    let ours = bundle_of(&cfg.config, &[read("layer0.tar"), read("layer1.tar")]).unwrap();
    let (want, mut got) = (list(&read("bundle.tar")), list(&ours));
    let escape = got.iter().position(|e| e.name == "rootfs/bin/escape").expect("the escaping symlink is kept");
    assert_eq!(got.remove(escape).link.as_deref(), Some("../../outside"));
    assert_eq!(want.iter().map(|e| &e.name).collect::<Vec<_>>(), got.iter().map(|e| &e.name).collect::<Vec<_>>());
    for (w, g) in want.iter().zip(&got) {
        if w.name == "config.json" {
            let json = |b: &[u8]| serde_json::from_slice::<serde_json::Value>(b).unwrap();
            assert_eq!(json(&w.body), json(&g.body));
            assert_eq!(Listed { body: Vec::new(), ..w.clone() }, Listed { body: Vec::new(), ..g.clone() });
        } else {
            assert_eq!(w, g);
        }
    }
}

fn layer(build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    build(&mut b);
    b.into_inner().unwrap()
}

fn header() -> tar::Header {
    let mut h = tar::Header::new_ustar();
    h.set_uid(0);
    h.set_gid(0);
    h.set_mtime(0);
    h
}

/// Writes the name as given, since the builder refuses the absolute names some layers have.
fn file(b: &mut tar::Builder<Vec<u8>>, name: &str, body: &str) {
    let mut h = header();
    h.set_entry_type(tar::EntryType::Regular);
    h.set_mode(0o644);
    h.set_size(body.len() as u64);
    h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
    h.set_cksum();
    b.append(&h, body.as_bytes()).unwrap();
}

fn symlink(b: &mut tar::Builder<Vec<u8>>, name: &str, target: &str) {
    let mut h = header();
    h.set_entry_type(tar::EntryType::Symlink);
    h.set_mode(0o777);
    h.set_size(0);
    b.append_link(&mut h, name, target).unwrap();
}

#[test]
fn account_files_must_be_regular() {
    let l = layer(|b| symlink(b, "etc/passwd", "/run/passwd"));
    let root = ImageConfig { cmd: vec!["/bin/sh".into()], ..Default::default() };
    bundle_of(&root, std::slice::from_ref(&l)).expect("an image running as root needs no account files");
    let named = ImageConfig { user: "app".into(), ..root };
    let err = bundle_of(&named, &[l]).unwrap_err();
    assert!(err.to_string().contains("isn't a regular file"), "{err}");
}

#[test]
fn spool_limit() {
    let l = layer(|b| {
        file(b, "a", "1234");
        file(b, "b", "5678");
    });
    Flattener::new(spool(), 8).layer(|| Ok(&l[..])).expect("an image exactly at the limit fits");
    let err = Flattener::new(spool(), 7).layer(|| Ok(&l[..])).unwrap_err();
    assert!(err.to_string().contains("exceeds"), "{err}");
}

#[test]
fn pre_posix_regular_files() {
    let mut l = layer(|b| file(b, "old", "x"));
    // a pre-POSIX header flags a regular file with NUL.
    l[156] = 0;
    let mut h = tar::Header::from_byte_slice(&l[..512]).clone();
    h.set_cksum();
    l[..512].copy_from_slice(h.as_bytes());
    let (entries, _) = flatten(&[l]).unwrap();
    let names: Vec<_> = entries.iter().map(|e: &Entry| (e.name.to_string(), e.kind.clone())).collect();
    assert_eq!(names, [("old".to_owned(), Kind::Regular { offset: 0, size: 1 })]);
}

fn hardlink(b: &mut tar::Builder<Vec<u8>>, name: &str, target: &str) {
    let mut h = header();
    h.set_entry_type(tar::EntryType::Link);
    h.set_mode(0o644);
    h.set_size(0);
    b.append_link(&mut h, name, target).unwrap();
}

fn whiteout(b: &mut tar::Builder<Vec<u8>>, name: &str) {
    file(b, name, "");
}

/// Each entry's name, kind, and contents or link target, as text.
fn listing(layers: &[Vec<u8>]) -> Vec<(String, tar::EntryType, String)> {
    let (entries, spool) = flatten(layers).unwrap();
    entries
        .iter()
        .map(|e| {
            let shown = match &e.kind {
                Kind::Regular { offset, size } => {
                    let mut body = vec![0; usize::try_from(*size).unwrap()];
                    std::os::unix::fs::FileExt::read_exact_at(&spool, &mut body, *offset).unwrap();
                    String::from_utf8(body).unwrap()
                }
                Kind::Symlink(target) => String::from_utf8(target.clone()).unwrap(),
                Kind::Hardlink(target) => target.to_string(),
                _ => String::new(),
            };
            (e.name.to_string(), e.kind.entry_type(), shown)
        })
        .collect()
}

fn regular(name: &str, body: &str) -> (String, tar::EntryType, String) {
    (name.into(), tar::EntryType::Regular, body.into())
}

fn link(name: &str, target: &str) -> (String, tar::EntryType, String) {
    (name.into(), tar::EntryType::Link, target.into())
}

#[test]
fn symlinks_climbing_above_the_root_replace_lower_files() {
    let lower = layer(|b| {
        file(b, "bin/x", "old");
        file(b, "bin/..data", "old");
    });
    let upper = layer(|b| {
        symlink(b, "bin/x", "../../../lib/x");
        symlink(b, "bin/..data", "..data2");
    });
    let sym = |name: &str, target: &str| (name.to_owned(), tar::EntryType::Symlink, target.to_owned());
    assert_eq!(listing(&[lower, upper]), [sym("bin/..data", "..data2"), sym("bin/x", "../../../lib/x")]);
}

#[test]
fn leading_slashes_name_the_same_file() {
    let lower = layer(|b| {
        file(b, "/etc/passwd", "lower");
        file(b, "/etc/group", "lower");
    });
    let upper = layer(|b| {
        file(b, "etc/passwd", "upper");
        whiteout(b, "etc/.wh.group");
    });
    assert_eq!(listing(&[lower, upper]), [regular("etc/passwd", "upper")]);
}

#[test]
fn hardlinks_keep_the_contents_upper_layers_remove_or_replace() {
    let lower = layer(|b| {
        file(b, "usr/bin/perl", "perl 5.36");
        hardlink(b, "usr/bin/perl5.36", "usr/bin/perl");
        hardlink(b, "usr/bin/perl5", "/usr/bin/perl");
        file(b, "usr/bin/vi", "vim 9");
        hardlink(b, "usr/bin/vim", "usr/bin/vi");
        file(b, "usr/bin/sh", "dash");
        hardlink(b, "usr/bin/dash", "usr/bin/sh");
    });
    let upper = layer(|b| {
        whiteout(b, "usr/bin/.wh.perl");
        file(b, "usr/bin/vi", "nvi");
    });
    assert_eq!(
        listing(&[lower, upper]),
        [
            regular("usr/bin/perl5.36", "perl 5.36"),
            regular("usr/bin/sh", "dash"),
            regular("usr/bin/vi", "nvi"),
            regular("usr/bin/vim", "vim 9"),
            link("usr/bin/dash", "usr/bin/sh"),
            link("usr/bin/perl5", "usr/bin/perl5.36"),
        ]
    );
}

#[test]
fn hardlinks_into_lower_layers() {
    let bottom = layer(|b| {
        file(b, "kept", "bottom kept");
        file(b, "removed", "bottom removed");
    });
    let middle = layer(|b| {
        hardlink(b, "kept-link", "kept");
        hardlink(b, "removed-link", "removed");
    });
    let top = layer(|b| whiteout(b, ".wh.removed"));
    assert_eq!(
        listing(&[bottom, middle, top]),
        [regular("kept", "bottom kept"), regular("removed-link", "bottom removed"), link("kept-link", "kept")]
    );
}

#[rstest]
#[case::dotdot("dir/.wh...")]
#[case::dot("dir/.wh..")]
#[case::empty("dir/.wh.")]
#[case::top_level_dotdot(".wh...")]
fn whiteouts_must_name_a_file(#[case] name: &str) {
    let bottom = layer(|b| file(b, "dir/f", "x"));
    let top = layer(|b| whiteout(b, name));
    let err = flatten(&[bottom, top]).unwrap_err();
    assert!(err.to_string().contains("names no file in its directory"), "{err}");
}

#[test]
fn hardlinks_to_missing_files_fail() {
    let lone = layer(|b| hardlink(b, "a", "nowhere"));
    let err = flatten(&[lone]).unwrap_err();
    assert!(err.to_string().contains("which isn't in the image"), "{err}");

    let bottom = layer(|b| file(b, "dir/t", "x"));
    let middle = layer(|b| whiteout(b, ".wh.dir"));
    let top = layer(|b| hardlink(b, "a", "dir/t"));
    let err = flatten(&[bottom, middle, top]).unwrap_err();
    assert!(err.to_string().contains("hardlink a targets dir/t"), "{err}");

    let escaping = layer(|b| {
        file(b, "t", "x");
        hardlink(b, "a", "../t");
    });
    let err = flatten(&[escaping]).unwrap_err();
    assert!(err.to_string().contains("outside the image"), "{err}");
}

#[test]
fn gnu_sparse_files_expand() {
    // 512 bytes of data at 4 KiB, then a hole to 8 KiB, closed by GNU tar's empty final block.
    let l = layer(|b| {
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::GNUSparse);
        h.set_mode(0o644);
        h.set_mtime(0);
        h.set_uid(0);
        h.set_gid(0);
        h.set_size(512);
        let gnu = h.as_gnu_mut().unwrap();
        gnu.name[..6].copy_from_slice(b"sparse");
        for (block, (offset, len)) in gnu.sparse.iter_mut().zip([(4096_u64, 512_u64), (8192, 0)]) {
            block.offset.copy_from_slice(format!("{offset:011o}\0").as_bytes());
            block.numbytes.copy_from_slice(format!("{len:011o}\0").as_bytes());
        }
        gnu.set_real_size(8192);
        h.set_cksum();
        b.append(&h, &[b'x'; 512][..]).unwrap();
    });
    let want = [vec![0; 4096], vec![b'x'; 512], vec![0; 3584]].concat();
    assert_eq!(listing(&[l]), [regular("sparse", std::str::from_utf8(&want).unwrap())]);
}

#[test]
fn pax_sparse_files_are_refused() {
    let l = layer(|b| {
        b.append_pax_extensions([("GNU.sparse.major", &b"1"[..]), ("GNU.sparse.name", b"sparse")]).unwrap();
        file(b, "GNUSparseFile.0/sparse", "1\n0\n0\n");
    });
    let err = flatten(&[l]).unwrap_err();
    assert!(err.to_string().contains("PAX sparse file"), "{err}");
}

#[test]
fn layers_decompress_by_magic() {
    let plain = layer(|b| file(b, "a", "hello"));
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(&plain).unwrap();
    let gz = gz.finish().unwrap();
    let zst = ruzstd::encoding::compress_to_vec(Cursor::new(&plain), ruzstd::encoding::CompressionLevel::Fastest);
    for data in [plain.clone(), gz, zst] {
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(&data).unwrap();
        std::io::Seek::rewind(&mut f).unwrap();
        let mut out = Vec::new();
        decompress(f).unwrap().read_to_end(&mut out).unwrap();
        assert_eq!(out, plain);
    }
}

const PROCESS: &str = r#"{"root":{"path":"rootfs"},"process":{"args":["/bin/sh"]}}"#;

#[rstest]
#[case::valid(PROCESS, true, true)]
#[case::missing_rootfs(PROCESS, false, false)]
#[case::empty_args(r#"{"root":{"path":"rootfs"},"process":{"args":[]}}"#, true, true)]
#[case::missing_process(r#"{"root":{"path":"rootfs"}}"#, true, false)]
#[case::null_process(r#"{"root":{"path":"rootfs"},"process":null}"#, true, false)]
#[case::different_root(r#"{"root":{"path":"/elsewhere"},"process":{"args":["/bin/sh"]}}"#, true, false)]
#[case::invalid_json("{", true, false)]
fn checks_bundles_before_packing(#[case] config: &str, #[case] rootfs: bool, #[case] valid: bool) {
    let dir = tempfile::tempdir().unwrap();
    if rootfs {
        std::fs::create_dir(dir.path().join("rootfs")).unwrap();
    }
    std::fs::write(dir.path().join("config.json"), config).unwrap();
    assert_eq!(check_bundle(dir.path()).is_ok(), valid);
}
