//! A stream's cursor: the last sequence number it exported, as eight big-endian bytes, replaced atomically.

use std::{
    fs::{self, DirBuilder, OpenOptions},
    io::{self, Write as _},
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
};

use crate::StreamKey;

const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

pub(crate) async fn create_dir(dir: &Path) -> io::Result<()> {
    let dir = dir.to_owned();
    blocking(move || DirBuilder::new().recursive(true).mode(DIR_MODE).create(dir)).await
}

/// 0 if the stream doesn't have a cursor yet.
pub(crate) async fn load(path: &Path) -> io::Result<u64> {
    match tokio::fs::read(path).await {
        Ok(data) => {
            let data: [u8; 8] = data.try_into().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "log cursor isn't 8 bytes"))?;
            Ok(u64::from_be_bytes(data))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(err) => Err(err),
    }
}

pub(crate) async fn save(path: PathBuf, seq: u64) -> io::Result<()> {
    blocking(move || {
        let tmp = path.with_extension("cursor.tmp");
        let written = write_synced(&tmp, seq).and_then(|()| fs::rename(&tmp, &path));
        if written.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        written?;
        // the rename isn't durable until the directory is.
        fs::File::open(path.parent().unwrap_or(Path::new("."))).and_then(|dir| dir.sync_all())
    })
    .await
}

fn write_synced(path: &Path, seq: u64) -> io::Result<()> {
    let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(FILE_MODE).open(path)?;
    f.write_all(&seq.to_be_bytes())?;
    f.sync_all()
}

/// Removes cursors (and leftover temp files) for streams `live` doesn't know about. Anything else in `dir` stays.
pub(crate) async fn prune(dir: &Path, live: impl Fn(&StreamKey) -> bool) {
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(err) => return tracing::warn!(error = %err, "read log cursors"),
    };
    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => return,
            Err(err) => return tracing::warn!(error = %err, "read log cursors"),
        };
        let name = entry.file_name();
        let Some(name) = name.to_str().map(|n| n.trim_end_matches(".tmp").trim_end_matches(".cursor")) else { continue };
        let Ok(key) = name.parse::<StreamKey>() else { continue };
        if live(&key) || entry.file_type().await.is_ok_and(|t| t.is_dir()) {
            continue;
        }
        if let Err(err) = tokio::fs::remove_file(entry.path()).await {
            tracing::warn!(error = %err, "retire log cursor");
        }
    }
}

/// Removes the cursor (and any leftover temp file) for the stream `key` names.
pub(crate) async fn remove(dir: &Path, key: &StreamKey) {
    for name in [format!("{key}.cursor"), format!("{key}.cursor.tmp")] {
        match tokio::fs::remove_file(dir.join(name)).await {
            Err(err) if err.kind() != io::ErrorKind::NotFound => tracing::warn!(error = %err, "retire log cursor"),
            _ => {}
        }
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> io::Result<T> + Send + 'static) -> io::Result<T> {
    tokio::task::spawn_blocking(f).await.map_err(io::Error::other)?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cursors_round_trip_and_reject_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.cursor");
        assert_eq!(load(&path).await.unwrap(), 0, "a new stream starts from the beginning");
        save(path.clone(), 0x0102_0304_0506_0708).await.unwrap();
        assert_eq!(fs::read(&path).unwrap(), [1, 2, 3, 4, 5, 6, 7, 8], "big-endian");
        assert_eq!(load(&path).await.unwrap(), 0x0102_0304_0506_0708);
        assert!(!dir.path().join("a.cursor.tmp").exists());
        fs::write(&path, b"short").unwrap();
        assert_eq!(load(&path).await.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn remove_takes_only_its_streams_files() {
        let dir = tempfile::tempdir().unwrap();
        let (gone, kept) = (StreamKey([0xaa; 32]), StreamKey([0xbb; 32]));
        for name in [format!("{gone}.cursor"), format!("{gone}.cursor.tmp"), format!("{kept}.cursor")] {
            fs::write(dir.path().join(name), b"").unwrap();
        }
        remove(dir.path(), &gone).await;
        remove(dir.path(), &gone).await;
        let left: Vec<_> = fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        assert_eq!(left, [format!("{kept}.cursor")]);
    }

    #[tokio::test]
    async fn pruning_removes_only_dead_cursors() {
        let dir = tempfile::tempdir().unwrap();
        let (live, dead) = (StreamKey([0xaa; 32]), StreamKey([0xbb; 32]));
        let names = [format!("{live}.cursor"), format!("{dead}.cursor"), format!("{dead}.cursor.tmp"), "notes.txt".into()];
        for name in &names {
            fs::write(dir.path().join(name), b"").unwrap();
        }
        fs::create_dir(dir.path().join("c".repeat(64))).unwrap();
        prune(dir.path(), |key| *key == live).await;
        let mut left: Vec<_> = fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        left.sort();
        assert_eq!(left, [format!("{live}.cursor"), "c".repeat(64), "notes.txt".into()]);
    }
}
