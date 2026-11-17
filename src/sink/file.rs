//! Mirrors the audit log, line for line, to another file (for example on another disk).
//!
//! On open, a torn last line (an append cut short by a crash) is cut off and the file
//! fsynced, so the mirror only ever holds whole lines. A newly created mirror has its
//! directory fsynced too. The runner checks the mirror's last line against the log before
//! appending after it (see `Sink::already_has`).

use std::fs::File;
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

use super::{Delivery, Line, Sink, Tail};
use crate::audit::MAX_ENTRY;
use crate::err;
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
            let (dir, name) = util::split_path(&self.path)?;
            let dir = util::Dir::secure(&dir, true)?;
            let created = dir.lstat(name)?.is_none();
            let f = ctx(
                dir.open_at(name, libc::O_RDWR | libc::O_APPEND | libc::O_CREAT, 0o600),
                "cannot open mirror",
                &self.path,
            )?;
            util::check_data_file(&f.metadata()?, &self.path)?;
            if created {
                ctx(f.sync_all(), "cannot sync", &self.path)?;
                ctx(dir.sync(), "cannot sync", dir.path())?;
            }
            let end = last_line_end(&f, &self.path)?;
            let len = f.metadata()?.len();
            if end < len {
                eprintln!(
                    "bouncer: mirror {}: removing {} bytes of an incomplete last line",
                    self.path.display(),
                    len - end
                );
                ctx(f.set_len(end), "cannot truncate", &self.path)?;
                ctx(f.sync_data(), "cannot sync", &self.path)?;
            }
            self.file = Some(f);
        }
        Ok(self.file.as_mut().expect("opened above"))
    }
}

/// Reads the last `n` bytes before `end`.
fn read_back(f: &File, end: u64, n: u64) -> std::io::Result<Vec<u8>> {
    let start = end.saturating_sub(n);
    let mut buf = vec![0u8; (end - start) as usize];
    f.read_exact_at(&mut buf, start)?;
    Ok(buf)
}

/// The length of the file up to and including its last newline.
fn last_line_end(f: &File, path: &std::path::Path) -> Result<u64> {
    let len = f.metadata()?.len();
    let window = MAX_ENTRY as u64 + 1;
    let tail = ctx(read_back(f, len, window), "cannot read", path)?;
    match tail.iter().rposition(|&b| b == b'\n') {
        Some(i) => Ok(len - tail.len() as u64 + i as u64 + 1),
        None if len < window => Ok(0),
        None => Err(err!(
            "{}: the last {window} bytes hold no complete line; this is not a bouncer mirror",
            path.display()
        )),
    }
}

impl Sink for FileSink {
    fn fingerprint(&self) -> String {
        format!("file:{}", self.path.display())
    }

    fn batch_size(&self) -> usize {
        256
    }

    fn send(&mut self, batch: &[Line]) -> Result<Delivery> {
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
        Ok(Delivery::all(batch.len()))
    }

    /// The mirror's last line, if it belongs to `log_id` (seq 0 for an empty mirror or one
    /// whose last line is from another log), so entries written just before a crash, after
    /// the last saved cursor, are not appended twice.
    fn already_has(&mut self, log_id: &str) -> Result<Option<Tail>> {
        let path = self.path.clone();
        let f = self.open()?;
        let len = f.metadata()?.len();
        let tail = ctx(
            read_back(f, len, MAX_ENTRY as u64 + 1),
            "cannot read",
            &path,
        )?;
        let Some(body) = tail.strip_suffix(b"\n") else {
            return Ok(Some(Tail::default()));
        };
        let last = &body[body.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1)..];
        let v: serde_json::Value = serde_json::from_slice(last)
            .map_err(|_| err!("{}: the last line is not an audit entry", path.display()))?;
        if v["log_id"].as_str() != Some(log_id) {
            return Ok(Some(Tail::default()));
        }
        let seq = v["seq"]
            .as_u64()
            .ok_or_else(|| err!("{}: the last line has no seq", path.display()))?;
        Ok(Some(Tail {
            seq,
            raw: last.to_vec(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(seq: u64) -> (Vec<u8>, serde_json::Value) {
        let e = serde_json::json!({"seq": seq, "log_id": "L", "mac": format!("{seq:064}")});
        (serde_json::to_vec(&e).unwrap(), e)
    }

    #[test]
    fn mirrors_resumes_and_cuts_a_torn_tail() {
        let dir = std::env::temp_dir().join(format!("bouncer-filesink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("mirror.jsonl");
        let mut s = FileSink::new(path.clone());
        assert_eq!(s.already_has("L").unwrap(), Some(Tail::default()));
        let (raw1, e1) = line(1);
        let l = Line {
            raw: &raw1,
            seq: 1,
            log_id: "L",
            ts: "",
            mac: "",
            entry: &e1,
        };
        assert_eq!(s.send(&[l]).unwrap(), Delivery::all(1));
        let mut s = FileSink::new(path.clone());
        let t = s.already_has("L").unwrap().unwrap();
        assert_eq!((t.seq, &t.raw), (1, &raw1));
        assert_eq!(s.already_has("other").unwrap(), Some(Tail::default()));
        let good = [raw1.clone(), b"\n".to_vec()].concat();
        assert_eq!(std::fs::read(&path).unwrap(), good);

        // A crash in the middle of an append leaves a fragment: it is cut on open, and the
        // next entry starts on a line of its own.
        let (raw2, e2) = line(2);
        let mut torn = good.clone();
        torn.extend_from_slice(&raw2[..10]);
        std::fs::write(&path, &torn).unwrap();
        let mut s = FileSink::new(path.clone());
        assert_eq!(s.already_has("L").unwrap().unwrap().seq, 1);
        assert_eq!(std::fs::read(&path).unwrap(), good);
        let l = Line {
            raw: &raw2,
            seq: 2,
            log_id: "L",
            ts: "",
            mac: "",
            entry: &e2,
        };
        s.send(&[l]).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
        for l in text.lines() {
            serde_json::from_str::<serde_json::Value>(l).unwrap();
        }
        // A fragment with no newline at all is cut too.
        std::fs::write(&path, &raw2[..5]).unwrap();
        let mut s = FileSink::new(path.clone());
        assert_eq!(s.already_has("L").unwrap(), Some(Tail::default()));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
