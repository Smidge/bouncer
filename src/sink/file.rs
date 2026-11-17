//! Mirrors the audit log, line for line, to another file (for example on another disk).

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use super::{Line, Sink};
use crate::util::{self, Result, ctx};

pub struct FileSink {
    path: PathBuf,
    file: Option<File>,
}

impl FileSink {
    pub fn new(path: PathBuf) -> FileSink {
        FileSink { path, file: None }
    }

    fn open(&mut self) -> Result<&mut File> {
        if self.file.is_none() {
            let (dir, _) = util::split_path(&self.path)?;
            util::Dir::secure(&dir, true)?;
            let f = ctx(
                OpenOptions::new()
                    .read(true)
                    .append(true)
                    .create(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&self.path),
                "cannot open mirror",
                &self.path,
            )?;
            util::check_data_file(&f.metadata()?, &self.path)?;
            self.file = Some(f);
        }
        Ok(self.file.as_mut().expect("opened above"))
    }
}

impl Sink for FileSink {
    fn fingerprint(&self) -> String {
        format!("file:{}", self.path.display())
    }

    fn batch_size(&self) -> usize {
        256
    }

    fn send(&mut self, batch: &[Line]) -> Result<usize> {
        let mut buf = Vec::new();
        for l in batch {
            buf.extend_from_slice(l.raw);
            buf.push(b'\n');
        }
        let path = self.path.clone();
        let f = self.open()?;
        let len = f.metadata()?.len();
        let r = f.write_all(&buf).and_then(|_| f.sync_data());
        if let Err(e) = r {
            // Keep the mirror made of whole lines.
            let _ = f.set_len(len);
            self.file = None;
            return Err(util::Error(format!("writing {}: {e}", path.display())));
        }
        Ok(batch.len())
    }

    /// Reads the mirror's last line so entries written just before a crash (but after the
    /// last saved cursor) are not appended twice.
    fn already_has(&mut self, log_id: &str) -> Option<u64> {
        let f = self.open().ok()?;
        let len = f.metadata().ok()?.len();
        let start = len.saturating_sub(crate::audit::MAX_ENTRY as u64 + 1);
        f.seek(SeekFrom::Start(start)).ok()?;
        let mut tail = Vec::new();
        f.take(len - start).read_to_end(&mut tail).ok()?;
        let body = tail.strip_suffix(b"\n")?;
        let last = &body[body.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1)..];
        let v: serde_json::Value = serde_json::from_slice(last).ok()?;
        (v["log_id"].as_str() == Some(log_id)).then(|| v["seq"].as_u64())?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mirrors_and_resumes() {
        let dir = std::env::temp_dir().join(format!("bouncer-filesink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("mirror.jsonl");
        let mut s = FileSink::new(path.clone());
        assert_eq!(s.already_has("L"), None);
        let e1 = serde_json::json!({"seq": 1, "log_id": "L"});
        let raw1 = serde_json::to_vec(&e1).unwrap();
        let l = Line {
            raw: &raw1,
            seq: 1,
            log_id: "L",
            ts: "",
            mac: "",
            entry: &e1,
        };
        assert_eq!(s.send(&[l]).unwrap(), 1);
        let mut s = FileSink::new(path.clone());
        assert_eq!(s.already_has("L"), Some(1));
        assert_eq!(s.already_has("other"), None);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            [raw1, b"\n".to_vec()].concat()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
