//! Audit sinks: copies of the audit log somewhere the host cannot rewrite.
//!
//! The local log is the spool. Each sink has a thread that reads complete entries past its
//! cursor, but never past what the audit log has fsynced, hands them to the `Sink`, and then
//! saves the cursor (atomically, fsynced). The cursor is bound to the log (`log_id`), the
//! destination (`Sink::fingerprint`), and the last delivered entry's `seq` and `mac`; if the
//! log no longer continues from there, or the cursor or the destination is ahead of the log,
//! the sink stops and reports it instead of re-sending or skipping anything. A sink thread
//! that dies is restarted.
//!
//! An entry the destination refuses permanently (InfluxDB answering 400 for that one line,
//! a syslog datagram too large even as a summary) is quarantined: the sink records it in its
//! status and in an audit `sink_reject` entry, and moves on. More than
//! `MAX_REJECTED_IN_A_ROW` in a row looks like a configuration problem, so the sink stops.
//!
//! To add a sink: implement `Sink`, add a config variant in `config.rs`, and build it in
//! `build`.

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::audit::{self, Shared};
use crate::config::{SinkConfig, SinkKind};
use crate::err;
use crate::util::{self, Result};

pub mod file;
#[cfg(feature = "net")]
pub mod http;
#[cfg(feature = "net")]
pub mod influx;
#[cfg(feature = "net")]
pub mod s3;
pub mod syslog;

/// One audit entry, as it appears in the log.
#[derive(Clone, Copy)]
pub struct Line<'a> {
    /// The exact line, without the newline.
    pub raw: &'a [u8],
    pub seq: u64,
    pub log_id: &'a str,
    pub ts: &'a str,
    pub mac: &'a str,
    /// The parsed entry.
    pub entry: &'a serde_json::Value,
}

/// Consecutive permanently refused entries the runner quarantines before it stops.
pub const MAX_REJECTED_IN_A_ROW: u32 = 3;

/// What `Sink::send` achieved.
#[derive(Debug, Default, PartialEq)]
pub struct Delivery {
    /// How many entries (a prefix of the batch) are now durable at the destination.
    pub sent: usize,
    /// The entry right after that prefix was refused for good (it can never be delivered),
    /// and why. The runner quarantines it and continues.
    pub rejected: Option<String>,
}

impl Delivery {
    pub fn all(n: usize) -> Delivery {
        Delivery {
            sent: n,
            rejected: None,
        }
    }
}

/// The last entry of this log a destination holds.
#[derive(Debug, Default, PartialEq)]
pub struct Tail {
    /// 0 when it holds none.
    pub seq: u64,
    /// The exact line, without the newline.
    pub raw: Vec<u8>,
}

pub trait Sink: Send {
    /// Identifies the destination. A cursor saved for another destination is not reused.
    fn fingerprint(&self) -> String;

    /// Delivers entries in order. An error means none past the reported prefix were
    /// delivered and they should be retried later.
    fn send(&mut self, batch: &[Line]) -> Result<Delivery>;

    /// How many entries `send` takes at once.
    fn batch_size(&self) -> usize {
        1
    }

    /// The last entry of `log_id` the destination holds, if it can tell (lets the file sink
    /// skip entries it wrote just before a crash, after checking the last one is identical).
    fn already_has(&mut self, _log_id: &str) -> Result<Option<Tail>> {
        Ok(None)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Cursor {
    pub log_id: String,
    pub dest: String,
    pub seq: u64,
    pub offset: u64,
    pub mac: String,
}

impl Cursor {
    fn fresh(log_id: &str, dest: &str) -> Cursor {
        Cursor {
            log_id: log_id.into(),
            dest: dest.into(),
            mac: audit::GENESIS.into(),
            ..Default::default()
        }
    }

    pub fn load(path: &Path) -> Option<Cursor> {
        let data = std::fs::read(path).ok()?;
        serde_json::from_slice(&data).ok()
    }

    fn save(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_vec(self).map_err(|_| err!("cannot encode cursor"))?;
        util::write_file_atomic(path, &data, 0o600)
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SinkStatus {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub delivered_seq: u64,
    pub last_success: Option<String>,
    pub last_error: Option<String>,
    pub last_error_at: Option<String>,
    pub restarts: u32,
    /// Entries the destination refused for good, skipped and recorded in the audit log.
    #[serde(skip_serializing_if = "is_zero")]
    pub quarantined: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_quarantined: Option<String>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

pub type StatusHandle = Arc<Mutex<SinkStatus>>;

/// Builds a sink from config, loading its credentials.
pub fn build(cfg: &SinkConfig, host: &str, vars: &[String]) -> Result<Box<dyn Sink>> {
    let _ = vars; // used by the influxdb sink (net feature)
    Ok(match &cfg.kind {
        SinkKind::File { path } => Box::new(file::FileSink::new(path.clone())),
        SinkKind::Syslog(c) => Box::new(syslog::SyslogSink::new(c.clone(), host)),
        #[cfg(feature = "net")]
        SinkKind::S3(c) => Box::new(s3::S3Sink::new(c.clone(), host)?),
        #[cfg(feature = "net")]
        SinkKind::Influx(c) => Box::new(influx::InfluxSink::new(c.clone(), host, vars)?),
        #[cfg(feature = "net")]
        SinkKind::Http(c) => Box::new(http::HttpSink::new(c.clone())?),
        #[cfg(not(feature = "net"))]
        _ => {
            return Err(err!(
                "sink `{}` needs the `net` feature; this build has no HTTP client",
                cfg.name
            ));
        }
    })
}

type Factory = Box<dyn Fn() -> Result<Box<dyn Sink>> + Send + Sync>;

/// Starts a supervised sink thread.
pub fn spawn(
    name: String,
    kind: &'static str,
    factory: Factory,
    log: PathBuf,
    cursor: PathBuf,
    shared: Arc<Shared>,
) -> Result<StatusHandle> {
    let status = Arc::new(Mutex::new(SinkStatus {
        name: name.clone(),
        kind,
        delivered_seq: Cursor::load(&cursor).map_or(0, |c| c.seq),
        ..Default::default()
    }));
    let st = status.clone();
    std::thread::Builder::new()
        .name(format!("sink-{name}"))
        .stack_size(1 << 20)
        .spawn(move || {
            let mut backoff = Duration::from_secs(1);
            loop {
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(&factory, &log, &cursor, &shared, &st)
                }));
                let why = match r {
                    Ok(Ok(())) => return,
                    Ok(Err(e)) => e.0,
                    Err(_) => "sink thread panicked".to_string(),
                };
                eprintln!("bouncer: sink {name} stopped ({why}); restarting in {backoff:?}");
                set_error(&st, why);
                st.lock().unwrap_or_else(|e| e.into_inner()).restarts += 1;
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(Duration::from_secs(300));
            }
        })
        .map_err(|e| err!("cannot start sink thread: {e}"))?;
    Ok(status)
}

fn set_error(st: &StatusHandle, e: String) {
    let mut s = st.lock().unwrap_or_else(|e| e.into_inner());
    s.last_error = Some(e);
    s.last_error_at = Some(util::rfc3339_ms(util::now_ms()));
}

/// The per-line fields the runner checks.
#[derive(Deserialize)]
struct LineMeta {
    seq: u64,
    log_id: String,
    prev: String,
    #[serde(default)]
    ts: String,
}

struct Owned {
    raw: Vec<u8>,
    meta: LineMeta,
    mac: String,
    value: serde_json::Value,
    len: u64,
}

fn run(
    factory: &Factory,
    log: &Path,
    cursor_path: &Path,
    shared: &Shared,
    st: &StatusHandle,
) -> Result<()> {
    let mut sink = factory()?;
    let dest = sink.fingerprint();
    let log_id = shared.head().log_id;
    let mut cur = match Cursor::load(cursor_path) {
        Some(c) if c.log_id == log_id && c.dest == dest => c,
        Some(_) => {
            eprintln!(
                "bouncer: sink cursor {} is for another log or destination; starting from the first entry",
                cursor_path.display()
            );
            Cursor::fresh(&log_id, &dest)
        }
        None => Cursor::fresh(&log_id, &dest),
    };
    let name = st.lock().map(|s| s.name.clone()).unwrap_or_default();
    let ahead = |what: String| {
        err!(
            "{what}, beyond the audit log (head seq {}, {} bytes on disk). The log was truncated \
             or replaced; check it with `bouncer verify-log`, then move the destination aside or \
             delete {} to start this sink over",
            shared.head().seq,
            shared.durable.load(Ordering::Acquire),
            cursor_path.display()
        )
    };
    // What the destination already has: never behind the cursor, never past the log, and its
    // last entry must be the log's (checked when the log reaches it).
    let mut tail = sink
        .already_has(&log_id)?
        .filter(|t| t.seq > 0 || cur.seq > 0);
    if let Some(t) = &tail {
        if t.seq < cur.seq {
            return Err(err!(
                "the destination's last entry is seq {}, but the cursor says seq {} was delivered; \
                 it was truncated or replaced. Move it aside, or delete {} to send everything again",
                t.seq,
                cur.seq,
                cursor_path.display()
            ));
        }
        if t.seq > shared.head().seq {
            return Err(ahead(format!("the destination holds seq {}", t.seq)));
        }
    }
    let differs = |seq: u64| {
        err!(
            "the destination's last entry (seq {seq}) differs from the audit log's; it was \
             written from another log or changed. Move it aside to start over"
        )
    };
    if let Some(t) = &tail
        && t.seq == cur.seq
    {
        // The cursor's entry: compare with the MAC the cursor recorded.
        let v: Option<serde_json::Value> = serde_json::from_slice(&t.raw).ok();
        if t.seq > 0 && v.as_ref().and_then(|v| v["mac"].as_str()) != Some(cur.mac.as_str()) {
            return Err(differs(t.seq));
        }
        tail = None;
    }
    let mut backoff = Duration::from_secs(1);
    let mut rejected_in_a_row = 0;
    loop {
        let seen = shared.synced.current();
        let durable = shared.durable.load(Ordering::Acquire);
        if cur.offset > durable {
            return Err(ahead(format!(
                "the sink cursor is at seq {} (byte {})",
                cur.seq, cur.offset
            )));
        }
        if cur.offset == durable {
            shared.synced.wait(seen, Duration::from_secs(60));
            continue;
        }
        let batch = read_batch(log, &cur, durable, sink.batch_size().max(1))?;
        if batch.is_empty() {
            shared.synced.wait(seen, Duration::from_secs(60));
            continue;
        }
        // Entries the destination already has are skipped, not re-sent; the last of them
        // must be identical to the log's.
        let mut skip = 0;
        if let Some(t) = &tail {
            skip = batch.iter().take_while(|l| l.meta.seq <= t.seq).count();
            if let Some(o) = batch[..skip].iter().find(|o| o.meta.seq == t.seq) {
                if o.raw != t.raw {
                    return Err(differs(t.seq));
                }
                tail = None;
            }
        }
        let lines: Vec<Line> = batch[skip..]
            .iter()
            .map(|o| Line {
                raw: &o.raw,
                seq: o.meta.seq,
                log_id: &o.meta.log_id,
                ts: &o.meta.ts,
                mac: &o.mac,
                entry: &o.value,
            })
            .collect();
        let sent = if lines.is_empty() {
            Ok(Delivery::all(0))
        } else {
            sink.send(&lines)
        };
        let mut done = match &sent {
            Ok(d) => skip + d.sent.min(lines.len()),
            Err(_) => skip,
        };
        let mut quarantined = None;
        if let Ok(Delivery {
            rejected: Some(why),
            ..
        }) = &sent
            && done < batch.len()
        {
            rejected_in_a_row += 1;
            if rejected_in_a_row > MAX_REJECTED_IN_A_ROW {
                advance(&mut cur, &batch[..done]);
                cur.save(cursor_path)?;
                return Err(err!(
                    "{rejected_in_a_row} entries in a row were refused ({why}); that looks like a \
                     configuration problem rather than a bad entry, so the sink stopped at seq {}",
                    batch[done].meta.seq
                ));
            }
            quarantined = Some((batch[done].meta.seq, batch[done].mac.clone(), why.clone()));
            done += 1;
        } else if done > skip {
            rejected_in_a_row = 0;
        }
        if done > 0 {
            advance(&mut cur, &batch[..done]);
            cur.save(cursor_path)?;
            let mut s = st.lock().unwrap_or_else(|e| e.into_inner());
            s.delivered_seq = cur.seq;
            s.last_success = Some(util::rfc3339_ms(util::now_ms()));
            s.last_error = None;
        }
        if let Some((seq, mac, why)) = quarantined {
            let note = format!(
                "sink {name} skipped seq {seq} (mac {}): the destination refused it for good: {why}",
                &mac[..16.min(mac.len())]
            );
            eprintln!("bouncer: {note}");
            shared.note(note.clone());
            let mut s = st.lock().unwrap_or_else(|e| e.into_inner());
            s.quarantined += 1;
            s.last_quarantined = Some(note);
        }
        if let Err(e) = sent {
            set_error(st, e.0.clone());
            eprintln!("bouncer: sink {name} failed, retrying in {backoff:?}: {e}");
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(Duration::from_secs(300));
        } else {
            backoff = Duration::from_secs(1);
        }
    }
}

fn advance(cur: &mut Cursor, delivered: &[Owned]) {
    for o in delivered {
        cur.offset += o.len;
        cur.seq = o.meta.seq;
        cur.mac = o.mac.clone();
    }
}

/// Reads up to `max` complete entries after the cursor, checking that they continue it.
fn read_batch(log: &Path, cur: &Cursor, durable: u64, max: usize) -> Result<Vec<Owned>> {
    let mut f: File = util::ctx(util::open_nofollow(log), "cannot open audit log", log)?;
    if f.metadata()?.len() < cur.offset {
        return Err(err!(
            "the audit log is shorter than the sink cursor; it was truncated or replaced. \
             Check it with `bouncer verify-log`; delete the cursor file to send it again"
        ));
    }
    f.seek(SeekFrom::Start(cur.offset))?;
    let mut r = BufReader::new(f);
    let mut out = Vec::new();
    let (mut pos, mut seq, mut mac) = (cur.offset, cur.seq, cur.mac.clone());
    while out.len() < max && pos < durable {
        let mut line = Vec::new();
        let n = std::io::Read::take(&mut r, audit::MAX_ENTRY as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if n == 0 || line.last() != Some(&b'\n') || pos + n as u64 > durable {
            break;
        }
        line.pop();
        let value: serde_json::Value = serde_json::from_slice(&line)
            .map_err(|_| err!("audit log entry at byte {pos} is not JSON"))?;
        let meta: LineMeta = serde_json::from_value(value.clone())
            .map_err(|_| err!("audit log entry at byte {pos} lacks seq/log_id/prev"))?;
        let this_mac = value["mac"].as_str().unwrap_or("").to_string();
        if meta.log_id != cur.log_id || meta.seq != seq + 1 || meta.prev != mac {
            return Err(err!(
                "the audit log does not continue from the sink cursor (seq {seq}); it was rewritten or replaced. \
                 Check it with `bouncer verify-log`"
            ));
        }
        seq = meta.seq;
        mac = this_mac.clone();
        pos += n as u64;
        out.push(Owned {
            raw: line,
            meta,
            mac: this_mac,
            value,
            len: n as u64,
        });
    }
    Ok(out)
}

/// An HTTP agent for sinks: global timeout, no redirects, statuses returned as values.
#[cfg(feature = "net")]
pub(crate) fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .max_redirects(0)
        .build()
        .into()
}

#[cfg(feature = "net")]
pub(crate) fn snippet(resp: &mut ureq::http::Response<ureq::Body>) -> String {
    let text = resp
        .body_mut()
        .with_config()
        .limit(4096)
        .read_to_string()
        .unwrap_or_default();
    util::escape(&util::cap(&text, 300)).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditLog, Entry};

    /// A destination that records what it got and refuses chosen seqs.
    struct Fake {
        got: Arc<Mutex<Vec<u64>>>,
        refuse: Vec<u64>,
        tail: Option<Tail>,
    }

    impl Sink for Fake {
        fn fingerprint(&self) -> String {
            "fake".into()
        }
        fn batch_size(&self) -> usize {
            4
        }
        fn send(&mut self, batch: &[Line]) -> Result<Delivery> {
            for (i, l) in batch.iter().enumerate() {
                if self.refuse.contains(&l.seq) {
                    return Ok(Delivery {
                        sent: i,
                        rejected: Some(format!("seq {} is bad", l.seq)),
                    });
                }
                self.got.lock().unwrap().push(l.seq);
            }
            Ok(Delivery::all(batch.len()))
        }
        fn already_has(&mut self, _: &str) -> Result<Option<Tail>> {
            Ok(self.tail.take())
        }
    }

    fn log(tag: &str, n: u64) -> (std::path::PathBuf, AuditLog) {
        let dir = std::env::temp_dir().join(format!("bouncer-runner-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("audit.jsonl");
        let (mut log, _) = AuditLog::open(&path, zeroize::Zeroizing::new([1u8; 32]), true).unwrap();
        for _ in 0..n {
            log.append(Entry::new("ls", "h")).unwrap();
        }
        (path, log)
    }

    fn start(
        path: &Path,
        log: &AuditLog,
        refuse: Vec<u64>,
        tail: Option<Tail>,
    ) -> (StatusHandle, Arc<Mutex<Vec<u64>>>) {
        let got = Arc::new(Mutex::new(Vec::new()));
        let (g, cell) = (got.clone(), Mutex::new(Some((refuse, tail))));
        let factory: Factory = Box::new(move || {
            let (refuse, tail) = cell.lock().unwrap().take().unwrap_or_default();
            Ok(Box::new(Fake {
                got: g.clone(),
                refuse,
                tail,
            }) as Box<dyn Sink>)
        });
        let mut cursor = path.as_os_str().to_owned();
        cursor.push(".fake.cursor");
        let st = spawn(
            "fake".into(),
            "fake",
            factory,
            path.to_path_buf(),
            cursor.into(),
            log.shared.clone(),
        )
        .unwrap();
        (st, got)
    }

    fn wait(what: &str, mut f: impl FnMut() -> bool) {
        let t = std::time::Instant::now();
        while !f() {
            assert!(t.elapsed() < Duration::from_secs(10), "timed out: {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn refused_entries_are_quarantined_and_noted() {
        let (path, log) = log("q", 6);
        let (st, got) = start(&path, &log, vec![2, 5], None);
        wait("delivery", || st.lock().unwrap().delivered_seq == 6);
        assert_eq!(*got.lock().unwrap(), vec![1, 3, 4, 6]);
        let s = st.lock().unwrap().clone();
        assert_eq!(s.quarantined, 2);
        assert!(s.last_quarantined.unwrap().contains("seq 5"));
        let notes = log.shared.take_notes();
        assert_eq!(notes.len(), 2);
        assert!(notes[0].contains("skipped seq 2") && notes[0].contains("seq 2 is bad"));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn many_refusals_in_a_row_stop_the_sink() {
        let (path, log) = log("stop", 8);
        let (st, got) = start(&path, &log, vec![2, 3, 4, 5, 6], None);
        wait("stop", || st.lock().unwrap().last_error.is_some());
        let s = st.lock().unwrap().clone();
        assert!(s.last_error.unwrap().contains("configuration problem"));
        assert_eq!(s.quarantined, u64::from(MAX_REJECTED_IN_A_ROW));
        assert_eq!(*got.lock().unwrap(), vec![1]);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_cursor_or_destination_ahead_of_the_log_is_reported() {
        let (path, log) = log("ahead", 3);
        let cursor = Cursor {
            log_id: log.head().log_id.clone(),
            dest: "fake".into(),
            seq: 9,
            offset: 1 << 20,
            mac: "00".repeat(32),
        };
        let mut cpath = path.as_os_str().to_owned();
        cpath.push(".fake.cursor");
        cursor.save(Path::new(&cpath)).unwrap();
        let (st, got) = start(&path, &log, vec![], None);
        wait("error", || st.lock().unwrap().last_error.is_some());
        let e = st.lock().unwrap().last_error.clone().unwrap();
        assert!(e.contains("beyond the audit log"), "{e}");
        assert!(got.lock().unwrap().is_empty());
        std::fs::remove_file(&cpath).unwrap();

        // A destination holding entries the log does not have.
        let ahead = Tail {
            seq: 7,
            raw: b"{}".to_vec(),
        };
        let (st, _) = start(&path, &log, vec![], Some(ahead));
        wait("error", || st.lock().unwrap().last_error.is_some());
        let e = st.lock().unwrap().last_error.clone().unwrap();
        assert!(e.contains("destination holds seq 7"), "{e}");
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn a_destination_tail_must_match_the_log() {
        let (path, log) = log("tail", 3);
        let lines: Vec<Vec<u8>> = std::fs::read(&path)
            .unwrap()
            .split(|&b| b == b'\n')
            .map(<[u8]>::to_vec)
            .collect();
        // The destination already has 1 and 2: only 3 is sent.
        let tail = Tail {
            seq: 2,
            raw: lines[1].clone(),
        };
        let (st, got) = start(&path, &log, vec![], Some(tail));
        wait("delivery", || st.lock().unwrap().delivered_seq == 3);
        assert_eq!(*got.lock().unwrap(), vec![3]);
        std::fs::remove_file(path.with_extension("jsonl.fake.cursor")).unwrap();
        // Its seq 2 is a different line: stop instead of appending after it.
        let mut other = lines[1].clone();
        other[5] ^= 1;
        let (st, got) = start(&path, &log, vec![], Some(Tail { seq: 2, raw: other }));
        wait("error", || st.lock().unwrap().last_error.is_some());
        assert!(
            st.lock()
                .unwrap()
                .last_error
                .clone()
                .unwrap()
                .contains("differs")
        );
        assert!(got.lock().unwrap().is_empty());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}

#[cfg(all(test, feature = "net"))]
pub(crate) mod testutil {
    //! A tiny HTTP/1.1 server for sink and admission tests.
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    pub struct Req {
        pub method: String,
        pub path: String,
        pub headers: HashMap<String, String>,
        pub body: Vec<u8>,
    }

    pub type Handler = Arc<dyn Fn(&Req) -> (u16, String) + Send + Sync>;
    pub type HeaderHandler =
        Arc<dyn Fn(&Req) -> (u16, Vec<(String, String)>, String) + Send + Sync>;

    /// Starts a server; `handler` returns (status, body). Returns the port and the requests.
    pub fn serve(handler: Handler) -> (u16, Arc<Mutex<Vec<Req>>>) {
        serve_with_headers(Arc::new(move |r| {
            let (status, body) = handler(r);
            (status, vec![], body)
        }))
    }

    /// As `serve`, with response headers. HEAD answers carry no body.
    pub fn serve_with_headers(handler: HeaderHandler) -> (u16, Arc<Mutex<Vec<Req>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { continue };
                let (seen, handler) = (seen2.clone(), handler.clone());
                std::thread::spawn(move || {
                    let mut w = conn.try_clone().unwrap();
                    let mut r = BufReader::new(conn);
                    loop {
                        let mut line = String::new();
                        if r.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        let mut parts = line.split_whitespace();
                        let method = parts.next().unwrap_or("").to_string();
                        let path = parts.next().unwrap_or("").to_string();
                        let mut headers = HashMap::new();
                        loop {
                            let mut h = String::new();
                            if r.read_line(&mut h).unwrap_or(0) == 0 {
                                return;
                            }
                            let h = h.trim_end();
                            if h.is_empty() {
                                break;
                            }
                            if let Some((k, v)) = h.split_once(':') {
                                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                            }
                        }
                        let len: usize = headers
                            .get("content-length")
                            .and_then(|l| l.parse().ok())
                            .unwrap_or(0);
                        let mut body = vec![0; len];
                        if r.read_exact(&mut body).is_err() {
                            return;
                        }
                        let req = Req {
                            method,
                            path,
                            headers,
                            body,
                        };
                        let (status, extra, mut text) = handler(&req);
                        let head = req.method == "HEAD";
                        seen.lock().unwrap().push(req);
                        if status == 0 {
                            // Simulate a hang.
                            std::thread::sleep(std::time::Duration::from_secs(30));
                            return;
                        }
                        let mut headers = String::new();
                        for (k, v) in extra {
                            headers.push_str(&format!("{k}: {v}\r\n"));
                        }
                        let len = text.len();
                        if head {
                            text.clear();
                        }
                        let resp = format!(
                            "HTTP/1.1 {status} X\r\nContent-Length: {len}\r\nContent-Type: application/json\r\n{headers}\r\n{text}"
                        );
                        if w.write_all(resp.as_bytes()).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        (port, seen)
    }
}
