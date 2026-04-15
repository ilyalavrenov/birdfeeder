//! Turns registry images, or bundles already unpacked on the host, into the `SquashFS` blobs templates point at.
//! Image contents never get unpacked onto the host as files. The flattened layers stream straight into mksquashfs.

mod archive_path;
mod bundle;
mod flatten;
mod registry;
mod spec;

use std::{
    ffi::OsString,
    fs::File,
    io::{self, BufRead, BufReader, Read},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use anyhow::{Context as _, Result, bail, ensure};
use serde::{Deserialize, Serialize, de::IgnoredAny};
use sha2::{Digest as _, Sha256};
use tempfile::TempPath;

pub use registry::Platform;

/// cap on the spool. it holds every file of an untrusted image, so this keeps a layer from filling the host's disk.
const MAX_IMAGE_BYTES: u64 = 32 << 30;

/// A converted image.
#[derive(Debug, Serialize)]
pub struct Converted {
    /// the repository and manifest digest that was converted, so a tag can be pinned.
    pub image: String,
    pub path: PathBuf,
    pub sha256: String,
}

/// Pulls reference for platform using the local Docker credentials and writes its bundle to output. Registries
/// listed in insecure (`host[:port]`) get plain HTTP. Dropping the future stops the conversion, and the packing
/// thread cleans up its partial output.
pub async fn convert(reference: &str, platform: &Platform, insecure: &[String], output: &Path) -> Result<Converted> {
    let dir = output.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new(".")).to_owned();
    let pulled = registry::pull(reference, platform, insecure, &dir).await?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let _cancel = CancelOnDrop(cancelled.clone());
    let out = output.to_owned();
    let image = pulled.image.clone();
    tokio::task::spawn_blocking(move || pack(&pulled, &dir, &out, &cancelled)).await.context("pack image")??;
    Ok(Converted { image, path: output.to_owned(), sha256: file_sha256(output)? })
}

/// A packed bundle directory.
#[derive(Debug, Serialize)]
pub struct Packed {
    pub path: PathBuf,
    pub sha256: String,
}

/// Packs the trusted, unpacked OCI bundle at dir into output. Dropping the future kills mksquashfs and removes its
/// partial output.
pub async fn pack_dir(dir: &Path, output: &Path) -> Result<Packed> {
    check_bundle(dir)?;
    let tmp = TempPath::try_from_path(tmp_path(output)).context("resolve output path")?;
    let out = tokio::process::Command::new("mksquashfs")
        .arg(dir)
        .arg(&tmp)
        .args(["-comp", "zstd", "-noappend", "-quiet"])
        .kill_on_drop(true)
        .output()
        .await
        .context("run mksquashfs")?;
    if !out.status.success() {
        bail!("mksquashfs: {}: {}", out.status, String::from_utf8_lossy(&out.stderr).trim());
    }
    tmp.persist(output).with_context(|| format!("publish {}", output.display()))?;
    Ok(Packed { path: output.to_owned(), sha256: file_sha256(output)? })
}

/// Rejects a bundle the guest couldn't run, so you find out at pack time and not when a template boots.
fn check_bundle(dir: &Path) -> Result<()> {
    #[derive(Deserialize)]
    struct Config {
        root: Root,
        // args may be empty when the template's container args supply the command.
        process: Option<IgnoredAny>,
    }
    #[derive(Deserialize)]
    struct Root {
        path: String,
    }
    let data = std::fs::read(dir.join("config.json")).context("read bundle config")?;
    let config: Config = serde_json::from_slice(&data).context("parse bundle config")?;
    ensure!(config.root.path == "rootfs", "bundle root.path must be rootfs");
    ensure!(config.process.is_some(), "bundle config needs a process");
    ensure!(dir.join("rootfs").is_dir(), "bundle needs a rootfs directory");
    Ok(())
}

fn tmp_path(output: &Path) -> PathBuf {
    let mut tmp = OsString::from(output);
    tmp.push(".tmp");
    tmp.into()
}

/// Sets the flag when `convert`'s future drops. The packing thread outlives the future and checks it.
struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

fn pack(pulled: &registry::Pulled, dir: &Path, output: &Path, cancelled: &AtomicBool) -> Result<()> {
    // declared before squash so it drops after. mksquashfs has to be dead before we remove its partial output.
    let tmp = TempPath::try_from_path(tmp_path(output)).context("resolve output path")?;
    let (squash, stdin) = Mksquashfs::start(&tmp)?;
    let spool = tempfile::Builder::new().prefix(".ociimage-spool-").tempfile_in(dir).context("create spool")?;
    let mut flat = flatten::Flattener::new(spool.reopen().context("open spool")?, MAX_IMAGE_BYTES);
    for layer in pulled.layers.iter().rev() {
        flat.layer(|| {
            let file = layer.reopen().context("open layer")?;
            Ok(Cancellable { inner: decompress(file).context("read layer")?, cancelled })
        })?;
    }
    let (entries, spool) = flat.finish()?;
    bundle::write(&pulled.config, &entries, &spool, stdin, cancelled)?;
    squash.finish()?;
    tmp.persist(output).with_context(|| format!("publish {}", output.display()))?;
    Ok(())
}

/// Layers can be gzip, zstd or plain tar no matter what their media type says, so go by the magic number.
fn decompress(file: File) -> io::Result<Box<dyn Read + Send>> {
    let mut r = BufReader::new(file);
    let head = r.fill_buf()?;
    Ok(if head.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::bufread::MultiGzDecoder::new(r))
    } else if head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Box::new(ruzstd::decoding::StreamingDecoder::new(r).map_err(io::Error::other)?)
    } else {
        Box::new(r)
    })
}

struct Cancellable<'a, R> {
    inner: R,
    cancelled: &'a AtomicBool,
}

impl<R: Read> Read for Cancellable<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(io::Error::other("cancelled"));
        }
        self.inner.read(buf)
    }
}

/// mksquashfs packing a tar from its stdin.
struct Mksquashfs {
    child: KillOnDrop,
    stderr: thread::JoinHandle<Vec<u8>>,
}

/// If this drops before it's waited on, mksquashfs gets killed so it never packs a truncated stream.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        // both are no-ops once the child's been waited on.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Mksquashfs {
    fn start(tmp: &Path) -> Result<(Self, ChildStdin)> {
        // fixed root and creation times keep the output's digest a function of the image alone.
        let mut child = Command::new("mksquashfs")
            .arg("-")
            .arg(tmp)
            .args(["-tar", "-comp", "zstd", "-noappend", "-quiet", "-exit-on-error", "-mkfs-time", "0", "-root-time", "0"])
            .args(["-root-mode", "0755", "-root-uid", "0", "-root-gid", "0"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("start mksquashfs")?;
        let stdin = child.stdin.take().expect("stdin is piped");
        let mut err = child.stderr.take().expect("stderr is piped");
        let stderr = thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = err.read_to_end(&mut buf);
            buf
        });
        Ok((Self { child: KillOnDrop(child), stderr }, stdin))
    }

    /// Waits for mksquashfs to pack the tar written to its stdin, which must be closed by now.
    fn finish(self) -> Result<()> {
        let Self { mut child, stderr } = self;
        let status = child.0.wait().context("wait for mksquashfs")?;
        let stderr = stderr.join().unwrap_or_default();
        ensure!(status.success(), "mksquashfs: {status}: {}", String::from_utf8_lossy(&stderr).trim());
        Ok(())
    }
}

fn file_sha256(path: &Path) -> Result<String> {
    let mut f = File::open(path).context("hash output")?;
    let mut h = digest_io::IoWrapper(Sha256::new());
    io::copy(&mut f, &mut h).context("hash output")?;
    Ok(hex::encode(h.0.finalize()))
}

#[cfg(test)]
mod tests;
