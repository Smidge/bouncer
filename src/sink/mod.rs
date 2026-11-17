//! Audit sinks: copies of the audit log somewhere the host cannot rewrite.
//!
//! The local log is the spool. Each sink has a thread that reads complete entries past its
//! cursor, but never past what the audit log has fsynced, hands them to the `Sink`, and then
//! saves the cursor (atomically, fsynced). The cursor is bound to the log (`log_id`), the
//! destination (`Sink::fingerprint`), and the last delivered entry's `seq` and `mac`; if the
//! log no longer continues from there, the sink stops and reports it instead of re-sending
//! or skipping anything. A sink thread that dies is restarted.
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

pub trait Sink: Send {
    /// Identifies the destination. A cursor saved for another destination is not reused.
    fn fingerprint(&self) -> String;

    /// Delivers entries in order and returns how many (a prefix of `batch`) are now durable
    /// at the destination. An error means none of the rest were delivered.
    fn send(&mut self, batch: &[Line]) -> Result<usize>;

    /// How many entries `send` takes at once.
    fn batch_size(&self) -> usize {
        1
    }

    /// The highest seq of `log_id` the destination already holds, if it can tell (lets the
    /// file sink skip entries it wrote just before a crash).
    fn already_has(&mut self, _log_id: &str) -> Option<u64> {
        None
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
    let skip_to = sink.already_has(&log_id).unwrap_or(0);
    let mut backoff = Duration::from_secs(1);
    loop {
        let seen = shared.synced.current();
        let durable = shared.durable.load(Ordering::Acquire);
        if cur.offset >= durable {
            shared.synced.wait(seen, Duration::from_secs(60));
            continue;
        }
        let batch = read_batch(log, &cur, durable, sink.batch_size().max(1))?;
        if batch.is_empty() {
            shared.synced.wait(seen, Duration::from_secs(60));
            continue;
        }
        // Entries the destination already has are skipped, not re-sent.
        let skip = batch.iter().take_while(|l| l.meta.seq <= skip_to).count();
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
            Ok(0)
        } else {
            sink.send(&lines)
        };
        let done = match &sent {
            Ok(n) => skip + (*n).min(lines.len()),
            Err(_) => skip,
        };
        if done > 0 {
            for o in &batch[..done] {
                cur.offset += o.len;
                cur.seq = o.meta.seq;
                cur.mac = o.mac.clone();
            }
            cur.save(cursor_path)?;
            let mut s = st.lock().unwrap_or_else(|e| e.into_inner());
            s.delivered_seq = cur.seq;
            s.last_success = Some(util::rfc3339_ms(util::now_ms()));
            s.last_error = None;
        }
        if let Err(e) = sent {
            set_error(st, e.0.clone());
            eprintln!(
                "bouncer: sink {} failed, retrying in {backoff:?}: {e}",
                st.lock().map(|s| s.name.clone()).unwrap_or_default()
            );
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(Duration::from_secs(300));
        } else {
            backoff = Duration::from_secs(1);
        }
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

    /// Starts a server; `handler` returns (status, body). Returns the port and the requests.
    pub fn serve(handler: Handler) -> (u16, Arc<Mutex<Vec<Req>>>) {
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
                        let (status, text) = handler(&req);
                        seen.lock().unwrap().push(req);
                        if status == 0 {
                            // Simulate a hang.
                            std::thread::sleep(std::time::Duration::from_secs(30));
                            return;
                        }
                        let resp = format!(
                            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{text}",
                            text.len()
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
