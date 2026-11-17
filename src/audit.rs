//! Append-only JSONL audit log with a SHA-256 hash chain.
//!
//! Each line is one JSON object whose `prev` field is the hex SHA-256 of the previous line's
//! exact bytes (without the newline). The first entry's `prev` is 64 zeros. Editing, removing
//! or reordering any line breaks the chain at the following line, which `verify` reports.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use serde::Serialize;

use crate::err;
use crate::peer::{ChainEntry, CtxValue, PeerCred};
use crate::util::{self, Result, ctx};

/// In "async" mode, appended entries reach the disk within about this long.
const SYNC_INTERVAL: Duration = Duration::from_millis(500);

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Serialize)]
pub struct Entry {
    pub ts: String,
    pub seq: u64,
    /// get, exec, set or rm.
    pub op: &'static str,
    pub names: Vec<String>,
    pub reason: String,
    /// allow or deny.
    pub decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// ok, denied, not_found or error.
    pub result: &'static str,
    pub policy: &'static str,
    pub host: String,
    pub peer: PeerCred,
    pub cwd: Option<String>,
    pub attribution: &'static str,
    pub context: BTreeMap<String, CtxValue>,
    pub chain: Vec<ChainEntry>,
    pub prev: String,
}

/// A generation counter that threads can wait on (fsync and upload workers).
#[derive(Default)]
pub struct Notify {
    generation: Mutex<u64>,
    cv: Condvar,
}

impl Notify {
    pub fn bump(&self) {
        *self.generation.lock().unwrap() += 1;
        self.cv.notify_all();
    }

    pub fn current(&self) -> u64 {
        *self.generation.lock().unwrap()
    }

    /// Waits until the generation moves past `seen` or the timeout passes; returns the current one.
    pub fn wait(&self, seen: u64, timeout: Duration) -> u64 {
        let g = self.generation.lock().unwrap();
        let (g, _) = self
            .cv
            .wait_timeout_while(g, timeout, |g| *g == seen)
            .unwrap();
        *g
    }
}

pub struct AuditLog {
    file: File,
    seq: u64,
    prev: String,
    strict: bool,
    pub notify: Arc<Notify>,
}

/// Returns the last complete line of the file, if any.
fn last_line(file: &mut File) -> Result<Option<Vec<u8>>> {
    const TAIL: u64 = 256 * 1024;
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(len.saturating_sub(TAIL)))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    if buf.last() != Some(&b'\n') {
        return Err(err!(
            "audit log does not end with a complete entry (interrupted write?); check it with `bouncer verify-log`"
        ));
    }
    buf.pop();
    match buf.iter().rposition(|&b| b == b'\n') {
        Some(i) => Ok(Some(buf[i + 1..].to_vec())),
        None if len <= TAIL => Ok(Some(buf)),
        None => Err(err!("audit log's last entry is larger than {TAIL} bytes")),
    }
}

impl AuditLog {
    pub fn open(path: &Path, strict: bool) -> Result<AuditLog> {
        if let Some(dir) = path.parent() {
            util::ensure_dir(dir, 0o700)?;
        }
        let mut file = ctx(
            OpenOptions::new()
                .read(true)
                .append(true)
                .create(true)
                .mode(0o600)
                .open(path),
            "cannot open audit log",
            path,
        )?;
        let (seq, prev) = match last_line(&mut file)? {
            None => (0, GENESIS.to_string()),
            Some(line) => {
                let v: serde_json::Value = serde_json::from_slice(&line)
                    .map_err(|_| err!("last audit log entry is not valid JSON"))?;
                let seq = v["seq"]
                    .as_u64()
                    .ok_or_else(|| err!("last audit log entry has no seq"))?;
                (seq, util::sha256_hex(&line))
            }
        };
        let notify = Arc::new(Notify::default());
        if !strict {
            let f = file.try_clone()?;
            let n = notify.clone();
            std::thread::spawn(move || {
                let mut seen = 0;
                loop {
                    seen = n.wait(seen, Duration::from_secs(3600));
                    let _ = f.sync_data();
                    // Coalesce: at most one fsync per interval. On macOS an fsync in flight
                    // blocks appends to the same file, so syncing after every entry under
                    // load would add milliseconds to requests.
                    std::thread::sleep(SYNC_INTERVAL);
                }
            });
        }
        Ok(AuditLog {
            file,
            seq,
            prev,
            strict,
            notify,
        })
    }

    /// Fills in `seq` and `prev`, then appends the entry with a single write.
    pub fn append(&mut self, mut entry: Entry) -> Result<u64> {
        entry.seq = self.seq + 1;
        entry.prev = self.prev.clone();
        let mut line =
            serde_json::to_string(&entry).map_err(|_| err!("cannot encode audit entry"))?;
        let hash = util::sha256_hex(line.as_bytes());
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        if self.strict {
            self.file.sync_data()?;
        }
        self.seq = entry.seq;
        self.prev = hash;
        self.notify.bump();
        Ok(entry.seq)
    }
}

#[derive(Debug)]
pub struct VerifyReport {
    pub entries: u64,
    pub last_seq: u64,
    pub last_hash: String,
}

/// Checks the hash chain and sequence numbers of a whole log file.
pub fn verify(path: &Path) -> Result<VerifyReport> {
    let data = ctx(fs::read(path), "cannot read audit log", path)?;
    let mut prev = GENESIS.to_string();
    let mut last_seq = 0;
    let mut entries = 0;
    let body = data.strip_suffix(b"\n").unwrap_or(&data);
    if body.is_empty() {
        return Ok(VerifyReport {
            entries: 0,
            last_seq: 0,
            last_hash: prev,
        });
    }
    for (i, line) in body.split(|&b| b == b'\n').enumerate() {
        let n = i + 1;
        let v: serde_json::Value =
            serde_json::from_slice(line).map_err(|_| err!("line {n}: not valid JSON"))?;
        let seq = v["seq"]
            .as_u64()
            .ok_or_else(|| err!("line {n}: missing seq"))?;
        if v["prev"].as_str() != Some(prev.as_str()) {
            return Err(err!(
                "line {n} (seq {seq}): hash chain broken; the entry before it was changed, removed or reordered"
            ));
        }
        if entries > 0 && seq != last_seq + 1 {
            return Err(err!(
                "line {n}: seq {seq} does not follow {last_seq}; entries are missing or reordered"
            ));
        }
        prev = util::sha256_hex(line);
        last_seq = seq;
        entries += 1;
    }
    if !data.ends_with(b"\n") {
        return Err(err!(
            "line {entries}: last entry is not newline-terminated (interrupted write?)"
        ));
    }
    Ok(VerifyReport {
        entries,
        last_seq,
        last_hash: prev,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Entry {
        Entry {
            ts: util::rfc3339_ms(util::now_ms()),
            seq: 0,
            op: "get",
            names: vec!["X".into()],
            reason: "testing the chain".into(),
            decision: "allow",
            why: None,
            result: "ok",
            policy: "require-reason",
            host: "h".into(),
            peer: PeerCred {
                uid: 1,
                gid: 1,
                pid: 1,
            },
            cwd: None,
            attribution: "ok",
            context: BTreeMap::new(),
            chain: vec![],
            prev: String::new(),
        }
    }

    #[test]
    fn chain_round_trip_and_tamper() {
        let dir = std::env::temp_dir().join(format!("bouncer-audit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("audit.jsonl");
        {
            let mut log = AuditLog::open(&path, true).unwrap();
            for _ in 0..3 {
                log.append(entry()).unwrap();
            }
        }
        // Reopening continues the chain.
        let mut log = AuditLog::open(&path, true).unwrap();
        assert_eq!(log.append(entry()).unwrap(), 4);
        let r = verify(&path).unwrap();
        assert_eq!((r.entries, r.last_seq), (4, 4));

        let text = fs::read_to_string(&path).unwrap();
        fs::write(
            &path,
            text.replacen("testing the chain", "testing the chair", 1),
        )
        .unwrap();
        let e = verify(&path).unwrap_err().to_string();
        assert!(e.contains("line 2"), "{e}");

        let lines: Vec<&str> = text.lines().collect();
        fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert!(verify(&path).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
