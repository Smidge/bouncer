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
//! complete entry and the failure is recorded in `<log>.state` before anything is reported.
//! That file is created at its full size when the log is opened, and a failure only
//! overwrites its first bytes in place and fsyncs, so recording a failure does not need a
//! new file or new space when the disk is full. Every later append fails, and the daemon
//! refuses to start, until `bouncer repair` has reset the state.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::FileExt;
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

/// Size of `<log>.state`. It is written in full when created, so recording a failure later
/// only overwrites bytes that are already allocated.
const STATE_LEN: usize = 4096;
const STATE_OK: &[u8] = b"bouncer audit state 1: ok\n";
const STATE_FAILED: &[u8] = b"bouncer audit state 1: FAILED\n";

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

    /// Cuts optional attribution detail so the entry fits `MAX_ENTRY`: step 1 shortens the
    /// process chain and context values, step 2 drops the chain and working directory.
    /// Names, the reason, the decision and the admission record are never cut; an entry
    /// that is still too large is refused, and with it the request.
    fn shrink(&mut self, step: u8) {
        self.truncated = true;
        if let Some(a) = &mut self.attribution {
            a.shrink();
            a.cwd = a.cwd.as_deref().map(|c| util::cap(c, 100));
            for c in a.context.values_mut() {
                c.value = util::cap(&c.value, 64);
            }
            if step >= 2 {
                a.chain.clear();
                a.cwd = None;
            }
        }
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

/// `<log>.state`: whether the log has failed, kept in a file that is never resized.
struct StateFile {
    file: File,
}

impl StateFile {
    fn body(failed: Option<&str>) -> Vec<u8> {
        let mut b = match failed {
            None => STATE_OK.to_vec(),
            Some(why) => {
                let mut b = STATE_FAILED.to_vec();
                b.extend_from_slice(util::escape(&util::cap(why, 1000)).as_bytes());
                b.push(b'\n');
                b
            }
        };
        b.truncate(STATE_LEN - 1);
        b.resize(STATE_LEN - 1, b' ');
        b.push(b'\n');
        b
    }

    /// Overwrites the state in place and fsyncs it.
    fn set(&self, failed: Option<&str>) -> std::io::Result<()> {
        self.file.write_all_at(&Self::body(failed), 0)?;
        self.file.sync_data()
    }

    /// None if the state is ok, else why it is not. Anything unexpected counts as failed.
    fn read(&self) -> std::io::Result<Option<String>> {
        let mut buf = vec![0u8; STATE_LEN + 1];
        let mut n = 0;
        while n < buf.len() {
            match self.file.read_at(&mut buf[n..], n as u64)? {
                0 => break,
                k => n += k,
            }
        }
        if n != STATE_LEN {
            return Ok(Some(format!(
                "the state file has {n} bytes, not {STATE_LEN}"
            )));
        }
        if buf.starts_with(STATE_OK) {
            return Ok(None);
        }
        if let Some(rest) = buf[..n].strip_prefix(STATE_FAILED) {
            let why = rest.split(|&b| b == b'\n').next().unwrap_or_default();
            return Ok(Some(String::from_utf8_lossy(why).trim().to_string()));
        }
        Ok(Some("the state file is not recognised".into()))
    }

    /// Opens `<log>.state`, creating it (at full size, fsynced) if it does not exist.
    /// Returns the file and whether it was created.
    fn open(dir: &Dir, log_name: &OsStr) -> Result<(StateFile, bool)> {
        let name = state_name(log_name);
        let path = dir.path().join(&name);
        let created = dir.lstat(&name)?.is_none();
        let flags = libc::O_RDWR
            | if created {
                libc::O_CREAT | libc::O_EXCL
            } else {
                0
            };
        let file = ctx(dir.open_at(&name, flags, 0o600), "cannot open", &path)?;
        util::check_data_file(&ctx(file.metadata(), "cannot stat", &path)?, &path)?;
        let st = StateFile { file };
        if created {
            ctx(st.set(None), "cannot write", &path)?;
        }
        Ok((st, created))
    }
}

fn state_name(log_name: &OsStr) -> OsString {
    let mut m = log_name.to_os_string();
    m.push(".state");
    m
}

/// State shared with the fsync thread, the sinks and `status`.
#[derive(Default)]
pub struct Shared {
    failed_flag: AtomicBool,
    failed: Mutex<Option<String>>,
    /// Where the failed state is persisted; None only in tests that build `Shared` alone.
    state: Mutex<Option<StateFile>>,
    /// The failed state is on disk.
    persisted: AtomicBool,
    #[cfg(test)]
    fail_fsync: AtomicBool,
    /// Bytes written to the log.
    pub written: AtomicU64,
    /// Bytes known to be on disk. Sinks never read past this.
    pub durable: AtomicU64,
    /// Bumped on every append (wakes the fsync thread).
    pub appended: Notify,
    /// Bumped when `durable` grows (wakes sinks).
    pub synced: Notify,
    pub head: Mutex<Head>,
    /// Notes from sink threads, appended to the log as `sink_reject` entries by the daemon.
    notes: Mutex<Vec<String>>,
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

    /// Enters the failed state: first in memory (nothing more is appended or released), then
    /// on disk. The reason is only readable (`failed`, so in any answer or `status`) once it
    /// is on disk, because the lock is held while it is written. Returns an error if it could
    /// not be persisted; the daemon then stays failed in memory and the next latch retries.
    pub fn latch(&self, why: String) -> std::result::Result<(), String> {
        let mut f = self.failed.lock().unwrap_or_else(|e| e.into_inner());
        self.failed_flag.store(true, Ordering::Release);
        let why = f.get_or_insert(why).clone();
        if self.persisted.load(Ordering::Acquire) {
            return Ok(());
        }
        let r = match &*self.state.lock().unwrap_or_else(|e| e.into_inner()) {
            Some(st) => st.set(Some(&why)).map_err(|e| e.to_string()),
            None => Ok(()),
        };
        match &r {
            Ok(()) => {
                self.persisted.store(true, Ordering::Release);
                eprintln!(
                    "bouncer: AUDIT LOG FAILED, refusing all requests until `bouncer repair`: {why}"
                );
            }
            Err(e) => eprintln!(
                "bouncer: AUDIT LOG FAILED, refusing all requests: {why}. The failure could not be \
                 recorded on disk ({e}); do not restart the daemon before running `bouncer repair`"
            ),
        }
        drop(f);
        r
    }

    pub fn head(&self) -> Head {
        self.head.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Queues a note for the audit log (at most 1000 are kept until written).
    pub fn note(&self, n: String) {
        let mut q = self.notes.lock().unwrap_or_else(|e| e.into_inner());
        if q.len() < 1000 {
            q.push(n);
        }
    }

    pub fn take_notes(&self) -> Vec<String> {
        std::mem::take(&mut *self.notes.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

/// The vault state (generation and file hash) an audit entry commits to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultState {
    pub generation: u64,
    pub hash: String,
}

/// A mutation whose vault file was replaced but not known to be durable (`commit_uncertain`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Uncertain {
    pub txn: String,
    pub before: Option<VaultState>,
    pub after: VaultState,
}

/// Follows vault state through the log: mutations set it, `abort` entries undo the last one,
/// `commit_uncertain` marks it as undecided until a `reconcile` or `abort` settles it.
#[derive(Clone, Debug, Default)]
pub struct StateTracker {
    pub current: Option<VaultState>,
    /// The last mutation: (txn, state before it, its seq).
    pub last_txn: Option<(String, Option<VaultState>, u64)>,
    pub uncertain: Option<Uncertain>,
}

impl StateTracker {
    fn observe(&mut self, m: &Meta) {
        let same_txn = |t: &Option<(String, Option<VaultState>, u64)>| matches!((&m.txn, t), (Some(a), Some((b, _, _))) if a == b);
        match m.op.as_str() {
            "abort" => {
                if same_txn(&self.last_txn) {
                    let (_, before, _) = self.last_txn.take().expect("matched above");
                    self.current = before;
                    self.uncertain = None;
                }
                return;
            }
            "commit_uncertain" => {
                if same_txn(&self.last_txn)
                    && let Some(after) = self.current.clone()
                {
                    let (txn, before, _) = self.last_txn.clone().expect("matched above");
                    self.uncertain = Some(Uncertain { txn, before, after });
                }
                return;
            }
            "reconcile" => {
                if self.uncertain.as_ref().map(|u| &u.txn) == m.txn.as_ref() {
                    self.uncertain = None;
                }
                return;
            }
            _ => {}
        }
        if let (Some(generation), Some(hash)) = (m.vault_gen, &m.vault_hash) {
            let before = self.current.replace(VaultState {
                generation,
                hash: hash.clone(),
            });
            self.last_txn = m.txn.clone().map(|t| (t, before, m.seq));
            self.uncertain = None;
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
        // Written by bouncer before the state file existed.
        if dir.lstat(&marker_name(name))?.is_some() {
            return Err(err!(
                "an earlier audit log write failed ({} exists); fix the cause, run `bouncer repair`, then start again",
                dir.path().join(marker_name(name)).display()
            ));
        }
        let (state, state_created) = StateFile::open(&dir, name)?;
        if let Some(why) = ctx(
            state.read(),
            "cannot read",
            &dir.path().join(state_name(name)),
        )? {
            return Err(err!(
                "the audit log is in a failed state ({why}; recorded in {}). Fix the cause, run `bouncer repair`, then start again",
                dir.path().join(state_name(name)).display()
            ));
        }
        let created = dir.lstat(name)?.is_none();
        let file = ctx(
            dir.open_at(name, libc::O_RDWR | libc::O_APPEND | libc::O_CREAT, 0o600),
            "cannot open audit log",
            path,
        )?;
        util::check_data_file(&ctx(file.metadata(), "cannot stat", path)?, path)?;
        if created || state_created {
            ctx(dir.sync(), "cannot sync", dir.path())?;
        }
        let verified = verify_reader(&file, Some(&chain_key), None)?;
        let mut head = verified.head.clone();
        if head.log_id.is_empty() {
            head.log_id = util::random_hex::<16>()?;
        }
        let shared = Arc::new(Shared::default());
        *shared.state.lock().unwrap_or_else(|e| e.into_inner()) = Some(state);
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

    fn fail(&mut self, mut why: String) -> util::Error {
        // Cut back to the last complete entry so the log stays verifiable.
        if let Err(e) = self.file.set_len(self.len) {
            why.push_str(&format!("; truncating the partial entry also failed: {e}"));
        }
        match self.shared.latch(why.clone()) {
            Ok(()) => err!("audit log write failed: {why}"),
            Err(e) => err!("audit log write failed: {why} (and recording the failure failed: {e})"),
        }
    }

    /// Encodes the entry with its MAC, shrinking it if it is too large.
    fn encode(&self, e: &mut Entry) -> Result<(Vec<u8>, String)> {
        let mut s = serde_json::to_vec(&*e).map_err(|_| err!("cannot encode audit entry"))?;
        for step in 1..=2 {
            if s.len() + MAC_SUFFIX_LEN < MAX_ENTRY {
                break;
            }
            e.shrink(step);
            s = serde_json::to_vec(&*e).map_err(|_| err!("cannot encode audit entry"))?;
        }
        if s.len() + MAC_SUFFIX_LEN >= MAX_ENTRY {
            return Err(err!(
                "the audit entry would be larger than {MAX_ENTRY} bytes even without process details; refused"
            ));
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
            let r = f.sync_data();
            #[cfg(test)]
            let r = if sh.fail_fsync.load(Ordering::Acquire) {
                Err(std::io::Error::other("injected fsync failure"))
            } else {
                r
            };
            match r {
                Ok(()) => {
                    sh.durable.fetch_max(target, Ordering::AcqRel);
                    sh.synced.bump();
                }
                Err(e) => {
                    // The kernel may have dropped the dirty pages; nothing written since the
                    // last good fsync can be trusted to be on disk.
                    let _ = sh.latch(format!("background fsync failed: {e}"));
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

/// Offline repair: cuts an incomplete last line, verifies the rest and resets the failed
/// state (and removes the marker older versions wrote). Returns the verification result.
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
    let (state, _) = StateFile::open(&dir, name)?;
    ctx(
        state.file.set_len(STATE_LEN as u64),
        "cannot resize",
        &dir.path().join(state_name(name)),
    )?;
    ctx(
        state.set(None),
        "cannot write",
        &dir.path().join(state_name(name)),
    )?;
    match dir.unlink(&marker_name(name)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    dir.sync()?;
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
    fn failed_state_survives_restart_without_new_files() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp("latch");
        let dir = path.parent().unwrap().to_path_buf();
        let (mut log, _) = AuditLog::open(&path, key(), true).unwrap();
        log.append(entry()).unwrap();
        let state = dir.join("audit.jsonl.state");
        assert_eq!(fs::metadata(&state).unwrap().len(), STATE_LEN as u64);
        // No new file can be created in the directory (as when the disk is full): the
        // failure is still recorded, in the preallocated state file.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
        log.fail_after = Some(20);
        let e = log.append(entry()).unwrap_err().to_string();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!e.contains("recording the failure failed"), "{e}");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 2, "no new files");
        let text = fs::read_to_string(&state).unwrap();
        assert!(
            text.starts_with("bouncer audit state 1: FAILED\nwrite: injected"),
            "{text}"
        );
        assert_eq!(text.len(), STATE_LEN);
        drop(log);
        // A restart refuses to serve...
        let e = AuditLog::open(&path, key(), true)
            .err()
            .unwrap()
            .to_string();
        assert!(
            e.contains("failed state") && e.contains("bouncer repair"),
            "{e}"
        );
        // ...also when the state file was damaged rather than flipped.
        fs::write(&state, "ok").unwrap();
        assert!(AuditLog::open(&path, key(), true).is_err());
        // Repair resets it.
        repair(&path, Some(&key())).unwrap();
        assert_eq!(fs::metadata(&state).unwrap().len(), STATE_LEN as u64);
        let (mut log, _) = AuditLog::open(&path, key(), true).unwrap();
        assert_eq!(log.append(entry()).unwrap().seq, 2);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn background_fsync_failure_is_persisted() {
        let path = tmp("bgsync");
        let (mut log, _) = AuditLog::open(&path, key(), false).unwrap();
        log.shared.fail_fsync.store(true, Ordering::Release);
        log.append(entry()).unwrap();
        let t = std::time::Instant::now();
        while log.shared.failed().is_none() {
            assert!(
                t.elapsed() < Duration::from_secs(10),
                "fsync thread did not latch"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(log.shared.persisted.load(Ordering::Acquire));
        assert!(log.append(entry()).is_err());
        drop(log);
        let e = AuditLog::open(&path, key(), false)
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("background fsync failed"), "{e}");
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    /// The largest request the daemon accepts always fits in one entry with every name and
    /// the whole reason, however much attribution detail there is.
    #[test]
    fn worst_case_request_keeps_every_name() {
        use crate::peer::{ChainEntry, CtxOther, CtxValue};
        use crate::proto::{MAX_NAMES, MAX_REASON};
        let path = tmp("worst");
        let (mut log, _) = AuditLog::open(&path, key(), true).unwrap();
        // Control characters take 6 bytes each in JSON (\u0001).
        let ctl = |n: usize| "\u{1}".repeat(n);
        let mut e = entry();
        e.names = (0..MAX_NAMES)
            .map(|i| format!("{i:03}{}", "N".repeat(125)))
            .collect();
        e.reason = ctl(MAX_REASON);
        e.why = Some(format!("admission check denied the request: {}", ctl(1000)));
        e.admission = Some(AdmissionRecord {
            decision: "deny".into(),
            reasoning: ctl(1000),
            model: "m".into(),
            cached: false,
            error: Some(ctl(300)),
        });
        let mut at = Attribution {
            cwd: Some(ctl(512)),
            ..Default::default()
        };
        for i in 0..64 {
            at.chain.push(ChainEntry {
                pid: i,
                uid: Some(1),
                exe: Some(ctl(256)),
                argv: Some(ctl(700)),
                env: true,
            });
        }
        for v in 0..16 {
            at.context.insert(
                format!("CONTEXT_VARIABLE_NUMBER_{v}"),
                CtxValue {
                    value: ctl(256),
                    pid: 1,
                    other: (0..7)
                        .map(|p| CtxOther {
                            value: ctl(256),
                            pid: p,
                        })
                        .collect(),
                },
            );
        }
        e.attribution = Some(at);
        let names = e.names.clone();
        log.append(e).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.len() <= MAX_ENTRY);
        let v: serde_json::Value = serde_json::from_str(text.trim_end()).unwrap();
        assert_eq!(v["truncated"], true);
        assert_eq!(v["names"], serde_json::json!(names));
        assert_eq!(v["reason"].as_str().unwrap().chars().count(), MAX_REASON);
        verify(&path, Some(&key()), None).unwrap();
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
        // Names are never cut, so this entry is refused.
        let err = log.append(e).unwrap_err().to_string();
        assert!(err.contains("refused"), "{err}");
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
