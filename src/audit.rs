//! Append-only JSONL audit log with a keyed hash chain.
//!
//! Each line is one JSON object that ends with `"prev":"<hex>","mac":"<hex>"}`. `mac` is
//! HMAC-SHA256 over the line up to (not including) `,"mac":...`, closed with `}`, under a key
//! derived from the vault key (see `vault::chain_key`). `prev` is the previous line's `mac`
//! (64 zeros for the first entry), so editing, removing or reordering a line breaks the chain,
//! and nobody without the vault key can write a valid line. Removing lines from the end leaves
//! a valid shorter chain; anchor the head (`bouncer status`, a sink) to detect that.
//!
//! Failure is latched: if a write or fsync fails, the log is truncated back to its last
//! complete entry, a `<log>.failed` marker is written, and every later append fails until
//! `bouncer repair` has been run and the daemon restarted.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::err;
use crate::peer::{Attribution, PeerCred};
use crate::util::{self, Dir, Result, ctx};

/// In "async" mode, appended entries reach the disk within about this long.
const SYNC_INTERVAL: Duration = Duration::from_millis(500);

/// Hard limit on one line, including the newline. Writers shrink or refuse larger entries,
/// so every entry that can be written can be read back.
pub const MAX_ENTRY: usize = 64 * 1024;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// `,"mac":"` + 64 hex + `"}`
const MAC_SUFFIX_LEN: usize = 8 + 64 + 2;

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// What the admission model said, for the audit entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionRecord {
    pub decision: String,
    pub reasoning: String,
    pub model: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub cached: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Default, Serialize)]
pub struct Entry {
    pub ts: String,
    pub seq: u64,
    pub log_id: String,
    pub op: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// allow or deny (empty for records such as start/abort).
    #[serde(skip_serializing_if = "str::is_empty")]
    pub decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why: Option<String>,
    /// ok, denied, not_found or error.
    #[serde(skip_serializing_if = "str::is_empty")]
    pub result: &'static str,
    #[serde(skip_serializing_if = "str::is_empty")]
    pub policy: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admission: Option<AdmissionRecord>,
    /// Mutations: transaction id, and the vault generation and file hash it produces.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_gen: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_hash: Option<String>,
    /// Aggregated records (rejected connections).
    #[serde(skip_serializing_if = "is_zero")]
    pub count: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub uids: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<PeerCred>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribution: Option<Attribution>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
    pub prev: String,
}

impl Entry {
    pub fn new(op: &'static str, host: &str) -> Entry {
        Entry {
            ts: util::rfc3339_ms(util::now_ms()),
            op,
            host: host.to_string(),
            ..Default::default()
        }
    }

    fn shrink(&mut self) {
        self.truncated = true;
        self.reason = util::cap(&self.reason, 200);
        self.why = self.why.as_deref().map(|w| util::cap(w, 200));
        if let Some(a) = &mut self.admission {
            a.reasoning = util::cap(&a.reasoning, 500);
        }
        if let Some(a) = &mut self.attribution {
            a.shrink();
            a.cwd = a.cwd.as_deref().map(|c| util::cap(c, 100));
            for c in a.context.values_mut() {
                c.value = util::cap(&c.value, 64);
            }
        }
        self.names.truncate(8);
    }
}

/// A generation counter that threads can wait on.
#[derive(Default)]
pub struct Notify {
    generation: Mutex<u64>,
    cv: Condvar,
}

impl Notify {
    pub fn bump(&self) {
        *self.generation.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        self.cv.notify_all();
    }

    pub fn current(&self) -> u64 {
        *self.generation.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Waits until the generation moves past `seen` or the timeout passes; returns the current one.
    pub fn wait(&self, seen: u64, timeout: Duration) -> u64 {
        let g = self.generation.lock().unwrap_or_else(|e| e.into_inner());
        let (g, _) = self
            .cv
            .wait_timeout_while(g, timeout, |g| *g == seen)
            .unwrap_or_else(|e| e.into_inner());
        *g
    }
}

/// State shared with the fsync thread, the sinks and `status`.
#[derive(Default)]
pub struct Shared {
    failed_flag: AtomicBool,
    failed: Mutex<Option<String>>,
    /// Bytes written to the log.
    pub written: AtomicU64,
    /// Bytes known to be on disk. Sinks never read past this.
    pub durable: AtomicU64,
    /// Bumped on every append (wakes the fsync thread).
    pub appended: Notify,
    /// Bumped when `durable` grows (wakes sinks).
    pub synced: Notify,
    pub head: Mutex<Head>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Head {
    pub seq: u64,
    pub mac: String,
    pub log_id: String,
}

impl Shared {
    pub fn failed(&self) -> Option<String> {
        if !self.failed_flag.load(Ordering::Acquire) {
            return None;
        }
        self.failed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn latch(&self, why: String) {
        let mut f = self.failed.lock().unwrap_or_else(|e| e.into_inner());
        if f.is_none() {
            eprintln!("bouncer: AUDIT LOG FAILED, refusing all requests until repaired: {why}");
            *f = Some(why);
        }
        self.failed_flag.store(true, Ordering::Release);
    }

    pub fn head(&self) -> Head {
        self.head.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// The vault state (generation and file hash) an audit entry commits to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultState {
    pub generation: u64,
    pub hash: String,
}

/// Follows vault state through the log: mutations set it, `abort` entries undo the last one.
#[derive(Clone, Debug, Default)]
pub struct StateTracker {
    pub current: Option<VaultState>,
    /// The last mutation: (txn, state before it, its seq).
    pub last_txn: Option<(String, Option<VaultState>, u64)>,
}

impl StateTracker {
    fn observe(&mut self, m: &Meta) {
        if m.op == "abort" {
            if let (Some(t), Some((txn, before, _))) = (&m.txn, &self.last_txn)
                && t == txn
            {
                self.current = before.clone();
                self.last_txn = None;
            }
            return;
        }
        if let (Some(generation), Some(hash)) = (m.vault_gen, &m.vault_hash) {
            let before = self.current.replace(VaultState {
                generation,
                hash: hash.clone(),
            });
            self.last_txn = m.txn.clone().map(|t| (t, before, m.seq));
        }
    }
}

/// The fields verification needs from each line.
#[derive(Deserialize)]
struct Meta {
    seq: u64,
    #[serde(default)]
    log_id: String,
    prev: String,
    op: String,
    #[serde(default)]
    txn: Option<String>,
    #[serde(default)]
    vault_gen: Option<u64>,
    #[serde(default)]
    vault_hash: Option<String>,
}

#[derive(Debug, Default)]
pub struct Verified {
    pub entries: u64,
    pub head: Head,
    /// Bytes of complete, verified entries.
    pub len: u64,
    pub state: StateTracker,
    /// MACs were checked (false when verifying without the key).
    pub keyed: bool,
}

/// Splits a line into (signed body, mac hex).
fn split_mac(line: &[u8]) -> Option<(Vec<u8>, &str)> {
    if line.len() < MAC_SUFFIX_LEN + 2 || !line.ends_with(b"\"}") {
        return None;
    }
    let cut = line.len() - MAC_SUFFIX_LEN;
    let suffix = &line[cut..];
    if !suffix.starts_with(b",\"mac\":\"") {
        return None;
    }
    let mac = std::str::from_utf8(&suffix[8..72]).ok()?;
    if !mac.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut body = line[..cut].to_vec();
    body.push(b'}');
    Some((body, mac))
}

fn mac_hex(key: &[u8; 32], body: &[u8]) -> String {
    util::hex(&util::hmac_sha256(key, body))
}

/// Streams a log and checks every link: seq starts at 1 and increases by one, `prev` matches
/// the previous `mac`, `log_id` never changes, and (with a key) every `mac` is valid.
/// `expect_head` = (seq, mac) checks an externally anchored head is still in the log.
pub fn verify_reader(
    r: impl Read,
    key: Option<&[u8; 32]>,
    expect_head: Option<(u64, &str)>,
) -> Result<Verified> {
    let mut r = BufReader::with_capacity(64 * 1024, r);
    let mut v = Verified {
        head: Head {
            mac: GENESIS.into(),
            ..Default::default()
        },
        keyed: key.is_some(),
        ..Default::default()
    };
    let mut line = Vec::with_capacity(4096);
    let mut found_expected = false;
    loop {
        line.clear();
        let n = (&mut r)
            .take(MAX_ENTRY as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        let lineno = v.entries + 1;
        if line.last() != Some(&b'\n') {
            if n > MAX_ENTRY {
                return Err(err!("line {lineno}: longer than {MAX_ENTRY} bytes"));
            }
            return Err(err!(
                "line {lineno}: incomplete last entry (interrupted write); run `bouncer repair`"
            ));
        }
        line.pop();
        let (body, mac) = split_mac(&line).ok_or_else(|| {
            err!("line {lineno}: not a bouncer v2 audit entry (no mac); see `bouncer migrate-log`")
        })?;
        if let Some(k) = key
            && !util::ct_eq(mac_hex(k, &body).as_bytes(), mac.as_bytes())
        {
            return Err(err!(
                "line {lineno}: MAC does not match; the entry was changed, or the log was written with another key"
            ));
        }
        let m: Meta =
            serde_json::from_slice(&body).map_err(|_| err!("line {lineno}: not valid JSON"))?;
        if m.seq != v.head.seq + 1 {
            return Err(err!(
                "line {lineno}: seq {} does not follow {}; entries are missing or reordered",
                m.seq,
                v.head.seq
            ));
        }
        if m.prev != v.head.mac {
            return Err(err!(
                "line {lineno} (seq {}): hash chain broken; the entry before it was changed, removed or reordered",
                m.seq
            ));
        }
        if v.entries == 0 {
            v.head.log_id = m.log_id.clone();
        } else if m.log_id != v.head.log_id {
            return Err(err!(
                "line {lineno}: log_id changed; lines from another log were spliced in"
            ));
        }
        if let Some((s, h)) = expect_head
            && s == m.seq
        {
            if !h.eq_ignore_ascii_case(mac) {
                return Err(err!(
                    "seq {s} has mac {mac}, not the expected {h}: the log was rewritten from that point"
                ));
            }
            found_expected = true;
        }
        v.state.observe(&m);
        v.entries += 1;
        v.head.seq = m.seq;
        v.head.mac = mac.to_ascii_lowercase();
        v.len += n as u64;
    }
    if let Some((s, _)) = expect_head
        && !found_expected
    {
        return Err(err!(
            "the expected head seq {s} is not in the log (last seq {}): entries were removed from the end",
            v.head.seq
        ));
    }
    Ok(v)
}

/// Verifies a log file by path (not following symlinks).
pub fn verify(
    path: &Path,
    key: Option<&[u8; 32]>,
    expect: Option<(u64, &str)>,
) -> Result<Verified> {
    let f = ctx(util::open_nofollow(path), "cannot open audit log", path)?;
    verify_reader(f, key, expect)
}

/// Parses `SEQ:HASH` for `--expect-head`.
pub fn parse_head(s: &str) -> Result<(u64, String)> {
    let (seq, hash) = s
        .split_once(':')
        .ok_or_else(|| err!("--expect-head takes SEQ:HASH, as printed by `bouncer status`"))?;
    let seq = seq.parse().map_err(|_| err!("bad seq in --expect-head"))?;
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(err!("the hash in --expect-head must be 64 hex characters"));
    }
    Ok((seq, hash.to_ascii_lowercase()))
}

fn marker_name(name: &OsStr) -> OsString {
    let mut m = name.to_os_string();
    m.push(".failed");
    m
}

pub struct AuditLog {
    file: File,
    dir: Dir,
    name: OsString,
    len: u64,
    head: Head,
    chain_key: Zeroizing<[u8; 32]>,
    strict: bool,
    pub shared: Arc<Shared>,
    /// Test hook: fail the write after this many bytes.
    #[cfg(test)]
    fail_after: Option<usize>,
}

impl AuditLog {
    /// Opens (or creates) the log, verifies it from the first entry and returns it with the
    /// verification result.
    pub fn open(
        path: &Path,
        chain_key: Zeroizing<[u8; 32]>,
        strict: bool,
    ) -> Result<(AuditLog, Verified)> {
        let (dir, name) = util::split_path(path)?;
        let dir = Dir::secure(&dir, true)?;
        if dir.lstat(&marker_name(name))?.is_some() {
            return Err(err!(
                "an earlier audit log write failed ({} exists); fix the cause, run `bouncer repair`, then start again",
                dir.path().join(marker_name(name)).display()
            ));
        }
        let created = dir.lstat(name)?.is_none();
        let file = ctx(
            dir.open_at(name, libc::O_RDWR | libc::O_APPEND | libc::O_CREAT, 0o600),
            "cannot open audit log",
            path,
        )?;
        util::check_data_file(&ctx(file.metadata(), "cannot stat", path)?, path)?;
        if created {
            ctx(dir.sync(), "cannot sync", dir.path())?;
        }
        let verified = verify_reader(&file, Some(&chain_key), None)?;
        let mut head = verified.head.clone();
        if head.log_id.is_empty() {
            head.log_id = util::random_hex::<16>()?;
        }
        let shared = Arc::new(Shared::default());
        shared.written.store(verified.len, Ordering::Release);
        shared.durable.store(verified.len, Ordering::Release);
        *shared.head.lock().unwrap() = head.clone();
        if !strict {
            let f = file.try_clone()?;
            let sh = shared.clone();
            std::thread::Builder::new()
                .name("audit-fsync".into())
                .spawn(move || fsync_loop(f, sh))
                .map_err(|e| err!("cannot start the audit fsync thread: {e}"))?;
        }
        Ok((
            AuditLog {
                file,
                dir,
                name: name.to_os_string(),
                len: verified.len,
                head,
                chain_key,
                strict,
                shared,
                #[cfg(test)]
                fail_after: None,
            },
            verified,
        ))
    }

    pub fn head(&self) -> &Head {
        &self.head
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn path(&self) -> std::path::PathBuf {
        self.dir.path().join(&self.name)
    }

    fn fail(&mut self, why: String) -> util::Error {
        // Cut back to the last complete entry so the log stays verifiable.
        let _ = self.file.set_len(self.len);
        let _ = self.dir.write_atomic(
            &marker_name(&self.name),
            format!("{why}\n").as_bytes(),
            0o600,
        );
        self.shared.latch(why.clone());
        err!("audit log write failed: {why}")
    }

    /// Encodes the entry with its MAC, shrinking it if it is too large.
    fn encode(&self, e: &mut Entry) -> Result<(Vec<u8>, String)> {
        let mut s = serde_json::to_vec(&*e).map_err(|_| err!("cannot encode audit entry"))?;
        if s.len() + MAC_SUFFIX_LEN + 1 > MAX_ENTRY {
            e.shrink();
            s = serde_json::to_vec(&*e).map_err(|_| err!("cannot encode audit entry"))?;
            if s.len() + MAC_SUFFIX_LEN + 1 > MAX_ENTRY {
                return Err(err!("audit entry is larger than {MAX_ENTRY} bytes"));
            }
        }
        let mac = mac_hex(&self.chain_key, &s);
        s.pop(); // the closing brace
        s.extend_from_slice(b",\"mac\":\"");
        s.extend_from_slice(mac.as_bytes());
        s.extend_from_slice(b"\"}\n");
        Ok((s, mac))
    }

    /// Fills in seq, log_id and prev, then appends the entry with a single write.
    /// Returns the new head.
    pub fn append(&mut self, mut e: Entry) -> Result<Head> {
        if let Some(why) = self.shared.failed() {
            return Err(err!(
                "audit log is in a failed state ({why}); run `bouncer repair` and restart"
            ));
        }
        e.seq = self.head.seq + 1;
        e.log_id = self.head.log_id.clone();
        e.prev = self.head.mac.clone();
        let (line, mac) = self.encode(&mut e)?;
        if let Err(err) = self.write(&line) {
            return Err(self.fail(format!("write: {err}")));
        }
        if self.strict
            && let Err(err) = self.file.sync_data()
        {
            return Err(self.fail(format!("fsync: {err}")));
        }
        self.len += line.len() as u64;
        self.head = Head {
            seq: e.seq,
            mac,
            log_id: self.head.log_id.clone(),
        };
        *self.shared.head.lock().unwrap_or_else(|x| x.into_inner()) = self.head.clone();
        self.shared.written.store(self.len, Ordering::Release);
        if self.strict {
            self.shared.durable.store(self.len, Ordering::Release);
            self.shared.synced.bump();
        } else {
            self.shared.appended.bump();
        }
        Ok(self.head.clone())
    }

    fn write(&mut self, line: &[u8]) -> std::io::Result<()> {
        #[cfg(test)]
        if let Some(n) = self.fail_after {
            let n = n.min(line.len());
            self.file.write_all(&line[..n])?;
            return Err(std::io::Error::other("injected failure"));
        }
        self.file.write_all(line)
    }
}

fn fsync_loop(f: File, sh: Arc<Shared>) {
    let mut seen = 0;
    loop {
        seen = sh.appended.wait(seen, Duration::from_secs(3600));
        let target = sh.written.load(Ordering::Acquire);
        if target > sh.durable.load(Ordering::Acquire) {
            match f.sync_data() {
                Ok(()) => {
                    sh.durable.fetch_max(target, Ordering::AcqRel);
                    sh.synced.bump();
                }
                Err(e) => {
                    // The kernel may have dropped the dirty pages; nothing written since the
                    // last good fsync can be trusted to be on disk.
                    sh.latch(format!("background fsync failed: {e}"));
                    return;
                }
            }
        }
        // Coalesce: at most one fsync per interval. On macOS an fsync in flight blocks
        // appends to the same file, so syncing after every entry under load would add
        // milliseconds to requests.
        std::thread::sleep(SYNC_INTERVAL);
    }
}

/// Offline repair: cuts an incomplete last line, verifies the rest and removes the failure
/// marker. Returns the verification result.
pub fn repair(path: &Path, key: Option<&[u8; 32]>) -> Result<Verified> {
    let (dir, name) = util::split_path(path)?;
    let dir = Dir::secure(&dir, true)?;
    let f = ctx(
        dir.open_at(name, libc::O_RDWR, 0),
        "cannot open audit log",
        path,
    )?;
    util::check_data_file(&f.metadata()?, path)?;
    let len = f.metadata()?.len();
    // Find the end of the last complete line.
    let mut keep = 0u64;
    let mut r = BufReader::new(&f);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = r.read_until(b'\n', &mut buf)?;
        if n == 0 || buf.last() != Some(&b'\n') {
            break;
        }
        keep += n as u64;
    }
    if keep < len {
        eprintln!(
            "bouncer: removing {} bytes of an incomplete last entry",
            len - keep
        );
        f.set_len(keep)?;
        f.sync_all()?;
    }
    let mut f = f;
    std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(0))?;
    let v = verify_reader(&f, key, None)?;
    match dir.unlink(&marker_name(name)) {
        Ok(()) => dir.sync()?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(v)
}

/// Checks a version 1 log (unkeyed SHA-256 chain). Returns (entries, head hash).
pub fn verify_v1(path: &Path) -> Result<(u64, String)> {
    let mut r = BufReader::new(ctx(util::open_nofollow(path), "cannot open", path)?);
    let (mut prev, mut n, mut line) = (GENESIS.to_string(), 0u64, Vec::new());
    loop {
        line.clear();
        if r.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        if line.pop() != Some(b'\n') {
            return Err(err!("v1 log line {}: incomplete", n + 1));
        }
        let v: serde_json::Value =
            serde_json::from_slice(&line).map_err(|_| err!("v1 log line {}: not JSON", n + 1))?;
        if v["prev"].as_str() != Some(prev.as_str()) {
            return Err(err!("v1 log line {}: hash chain broken", n + 1));
        }
        prev = util::sha256_hex(&line);
        n += 1;
    }
    Ok((n, prev))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn key() -> Zeroizing<[u8; 32]> {
        Zeroizing::new([3u8; 32])
    }

    fn entry() -> Entry {
        let mut e = Entry::new("get", "h");
        e.names = vec!["X".into()];
        e.reason = "testing the chain".into();
        e.decision = "allow";
        e.result = "ok";
        e
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bouncer-audit-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir.join("audit.jsonl")
    }

    #[test]
    fn chain_round_trip_and_tamper() {
        let path = tmp("chain");
        {
            let (mut log, v) = AuditLog::open(&path, key(), true).unwrap();
            assert_eq!(v.entries, 0);
            for _ in 0..3 {
                log.append(entry()).unwrap();
            }
        }
        // Reopening verifies and continues the chain with the same log_id.
        let (mut log, v) = AuditLog::open(&path, key(), true).unwrap();
        assert_eq!(v.entries, 3);
        let head3 = v.head.clone();
        assert_eq!(log.append(entry()).unwrap().seq, 4);
        let r = verify(&path, Some(&key()), None).unwrap();
        assert_eq!((r.entries, r.head.seq), (4, 4));
        assert_eq!(r.head.log_id, head3.log_id);
        // Anchored head still present.
        verify(&path, Some(&key()), Some((3, &head3.mac))).unwrap();
        // The wrong key fails on the first line.
        assert!(verify(&path, Some(&[9u8; 32]), None).is_err());
        // Without a key the structure still verifies.
        assert!(!verify(&path, None, None).unwrap().keyed);

        let text = fs::read_to_string(&path).unwrap();
        // Editing a field breaks that line's MAC.
        fs::write(
            &path,
            text.replacen("testing the chain", "testing the chair", 1),
        )
        .unwrap();
        let e = verify(&path, Some(&key()), None).unwrap_err().to_string();
        assert!(e.contains("line 1") && e.contains("MAC"), "{e}");
        // Removing a middle line breaks the chain.
        let lines: Vec<&str> = text.lines().collect();
        fs::write(&path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert!(
            verify(&path, None, None)
                .unwrap_err()
                .to_string()
                .contains("seq")
        );
        // Truncating the tail verifies alone, but not against the anchored head.
        fs::write(&path, format!("{}\n{}\n", lines[0], lines[1])).unwrap();
        verify(&path, Some(&key()), None).unwrap();
        let e = verify(&path, Some(&key()), Some((3, &head3.mac)))
            .unwrap_err()
            .to_string();
        assert!(e.contains("removed from the end"), "{e}");
        // A partial last line is reported, and repair cuts it.
        fs::write(&path, format!("{}\n{}\n{{\"seq\":3", lines[0], lines[1])).unwrap();
        assert!(
            verify(&path, None, None)
                .unwrap_err()
                .to_string()
                .contains("incomplete")
        );
        assert_eq!(repair(&path, Some(&key())).unwrap().entries, 2);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn fails_closed_on_write_error() {
        let path = tmp("fail");
        let (mut log, _) = AuditLog::open(&path, key(), true).unwrap();
        log.append(entry()).unwrap();
        let good = fs::read(&path).unwrap();
        log.fail_after = Some(20);
        assert!(log.append(entry()).is_err());
        // Truncated back to the last complete entry, and latched.
        assert_eq!(fs::read(&path).unwrap(), good);
        log.fail_after = None;
        let e = log.append(entry()).unwrap_err().to_string();
        assert!(e.contains("failed state"), "{e}");
        assert!(log.shared.failed().is_some());
        drop(log);
        // The marker blocks a restart until repair.
        let e = AuditLog::open(&path, key(), true)
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("bouncer repair"), "{e}");
        repair(&path, Some(&key())).unwrap();
        let (mut log, v) = AuditLog::open(&path, key(), true).unwrap();
        assert_eq!(v.entries, 1);
        assert_eq!(log.append(entry()).unwrap().seq, 2);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn oversized_entries_shrink_or_fail() {
        let path = tmp("size");
        let (mut log, _) = AuditLog::open(&path, key(), true).unwrap();
        let mut e = entry();
        let mut at = Attribution::default();
        for i in 0..64 {
            at.chain.push(crate::peer::ChainEntry {
                pid: i,
                uid: None,
                exe: Some("\u{1}".repeat(256)),
                argv: Some("\u{1}".repeat(700)),
                env: true,
            });
        }
        e.attribution = Some(at);
        log.append(e).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.len() <= MAX_ENTRY);
        assert!(text.contains("\"truncated\":true"));
        verify(&path, Some(&key()), None).unwrap();
        let mut e = entry();
        e.names = vec!["n".repeat(MAX_ENTRY); 1];
        assert!(log.append(e).is_err());
        assert!(
            log.shared.failed().is_none(),
            "a size error is not an I/O failure"
        );
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn tracks_vault_state() {
        let path = tmp("state");
        let (mut log, _) = AuditLog::open(&path, key(), true).unwrap();
        let mut e = Entry::new("init", "h");
        e.vault_gen = Some(1);
        e.vault_hash = Some("a".into());
        log.append(e).unwrap();
        let mut e = entry();
        e.op = "set";
        e.txn = Some("t1".into());
        e.vault_gen = Some(2);
        e.vault_hash = Some("b".into());
        log.append(e).unwrap();
        let v = verify(&path, None, None).unwrap();
        assert_eq!(v.state.current.as_ref().unwrap().generation, 2);
        let mut e = Entry::new("abort", "h");
        e.txn = Some("t1".into());
        log.append(e).unwrap();
        let v = verify(&path, None, None).unwrap();
        assert_eq!(v.state.current.unwrap().hash, "a");
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
