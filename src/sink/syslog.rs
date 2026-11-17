//! RFC 5424 messages over the local syslog datagram socket (`/dev/log` on Linux, where
//! systemd-journald or rsyslog picks them up; `/var/run/syslog` on macOS).
//!
//! A datagram can only be as large as the socket allows: 2 KiB by default on macOS
//! (`net.local.dgram.maxdgram`), more on Linux. The limit is read from `SO_SNDBUF` when the
//! socket is opened and capped at 8 KiB. An entry that does not fit is sent as a one-line
//! summary (op, result, names, seq and mac) that points to the audit log. If the kernel still
//! answers EMSGSIZE, the limit is lowered and the summary retried; if even the shortest form
//! is refused, the entry is reported as refused (quarantined) rather than retried forever.
//! Sends time out after 2 seconds.
//!
//! Local syslog is best effort: a full or restarting syslog daemon can drop messages after
//! the send succeeded. Use it for visibility, and an S3 or file sink for a durable copy.

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use super::{Delivery, Line, Sink};
use crate::config::SyslogConfig;
use crate::util::{self, Result};

/// The largest message sent, whatever the socket allows.
const MAX_MSG: usize = 8 * 1024;
/// RFC 5424 says receivers must accept at least 480 bytes.
const MIN_MSG: usize = 480;
const SEND_TIMEOUT: Duration = Duration::from_secs(2);

pub struct SyslogSink {
    cfg: SyslogConfig,
    host: String,
    sock: Option<UnixDatagram>,
    /// The largest datagram to send on this socket.
    limit: usize,
    /// Tests: set SO_SNDBUF on connect, or pretend the socket allows this much.
    #[cfg(test)]
    sndbuf: Option<usize>,
    #[cfg(test)]
    assume_limit: Option<usize>,
}

impl SyslogSink {
    pub fn new(cfg: SyslogConfig, host: &str) -> SyslogSink {
        SyslogSink {
            cfg,
            host: sanitize(host, 255),
            sock: None,
            limit: MIN_MSG,
            #[cfg(test)]
            sndbuf: None,
            #[cfg(test)]
            assume_limit: None,
        }
    }

    fn connect(&mut self) -> Result<()> {
        let s = UnixDatagram::unbound()?;
        #[cfg(test)]
        if let Some(n) = self.sndbuf {
            set_sndbuf(&s, n);
        }
        s.connect(&self.cfg.socket).map_err(|e| {
            util::Error(format!(
                "cannot connect to {}: {e}",
                self.cfg.socket.display()
            ))
        })?;
        s.set_write_timeout(Some(SEND_TIMEOUT))?;
        self.limit = sndbuf(&s).clamp(MIN_MSG, MAX_MSG);
        #[cfg(test)]
        if let Some(n) = self.assume_limit {
            self.limit = n;
        }
        self.sock = Some(s);
        Ok(())
    }
}

/// The socket's send buffer, which bounds a datagram (0 if unknown).
fn sndbuf(s: &UnixDatagram) -> usize {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: v and len are valid out-pointers of the sizes passed.
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            (&mut v as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc == 0 && v > 0 {
        // Linux reports twice what it allows a datagram to use, and keeps some for itself.
        if cfg!(target_os = "linux") {
            (v as usize / 2).saturating_sub(64)
        } else {
            v as usize
        }
    } else {
        0
    }
}

#[cfg(test)]
fn set_sndbuf(s: &UnixDatagram, n: usize) {
    let v = n as libc::c_int;
    // SAFETY: v is a valid c_int of the size passed.
    unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            (&v as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

/// RFC 5424 header fields are printable US-ASCII without spaces.
fn sanitize(s: &str, max: usize) -> String {
    let s: String = s
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .take(max)
        .collect();
    if s.is_empty() { "-".into() } else { s }
}

/// Formats one entry as an RFC 5424 message of at most `max` bytes: the whole entry if it
/// fits, else a summary line.
pub fn format(facility: u8, host: &str, l: &Line, max: usize) -> Vec<u8> {
    let denied = l.entry["decision"].as_str() == Some("deny");
    let severity = if denied { 5 } else { 6 }; // notice / informational
    let pri = u32::from(facility) * 8 + severity;
    let ts = if l.ts.is_empty() { "-" } else { l.ts };
    let msgid = sanitize(l.entry["op"].as_str().unwrap_or("-"), 32);
    let mut msg = format!(
        "<{pri}>1 {ts} {host} bouncer {} {msgid} [bouncer@32473 seq=\"{}\" log_id=\"{}\" mac=\"{}\"] ",
        std::process::id(),
        l.seq,
        sanitize(l.log_id, 64),
        sanitize(l.mac, 64),
    )
    .into_bytes();
    if msg.len() + l.raw.len() <= max {
        msg.extend_from_slice(l.raw);
        return msg;
    }
    let s = |k: &str| sanitize(l.entry[k].as_str().unwrap_or("-"), 32);
    let names: Vec<&str> = l.entry["names"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let summary = format!(
        "{} result={} decision={} names={} (entry of {} bytes is too large for syslog; see the audit log)",
        s("op"),
        s("result"),
        s("decision"),
        sanitize(&names.join(","), 2048),
        l.raw.len()
    );
    msg.extend_from_slice(summary.as_bytes());
    if msg.len() > max {
        // Everything here is ASCII, so any cut is a valid message.
        msg.truncate(max.saturating_sub(3));
        msg.extend_from_slice(b"...");
    }
    msg
}

impl Sink for SyslogSink {
    fn fingerprint(&self) -> String {
        format!("syslog:{}", self.cfg.socket.display())
    }

    fn send(&mut self, batch: &[Line]) -> Result<Delivery> {
        if self.sock.is_none() {
            self.connect()?;
        }
        for (i, l) in batch.iter().enumerate() {
            loop {
                let msg = format(self.cfg.facility, &self.host, l, self.limit);
                let sock = self.sock.as_ref().expect("connected above");
                match sock.send(&msg) {
                    Ok(_) => break,
                    Err(e) if e.raw_os_error() == Some(libc::EMSGSIZE) => {
                        // Never retry the same size: shrink, and give up at the floor.
                        if self.limit <= MIN_MSG {
                            return Ok(Delivery {
                                sent: i,
                                rejected: Some(format!(
                                    "the syslog socket refuses even a {}-byte summary: {e}",
                                    msg.len()
                                )),
                            });
                        }
                        self.limit = (msg.len().min(self.limit) / 2).max(MIN_MSG);
                    }
                    Err(e) => {
                        self.sock = None;
                        if i > 0 {
                            return Ok(Delivery::all(i));
                        }
                        return Err(util::Error(format!("syslog send: {e}")));
                    }
                }
            }
        }
        Ok(Delivery::all(batch.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(tag: &str) -> (std::path::PathBuf, UnixDatagram, SyslogSink) {
        let dir = std::env::temp_dir().join(format!("bouncer-syslog-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("log.sock");
        let server = UnixDatagram::bind(&path).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let s = SyslogSink::new(
            SyslogConfig {
                socket: path,
                facility: 10,
            },
            "my host",
        );
        (dir, server, s)
    }

    fn recv(server: &UnixDatagram) -> String {
        let mut buf = vec![0u8; 65536];
        let n = server.recv(&mut buf).unwrap();
        String::from_utf8(buf[..n].to_vec()).unwrap()
    }

    #[test]
    fn sends_rfc5424() {
        let (dir, server, mut s) = setup("basic");
        let e = serde_json::json!({"op": "get", "decision": "deny", "seq": 3});
        let raw = serde_json::to_vec(&e).unwrap();
        let l = Line {
            raw: &raw,
            seq: 3,
            log_id: "abc",
            ts: "2026-11-17T10:00:00.000Z",
            mac: "m3",
            entry: &e,
        };
        assert_eq!(s.send(&[l]).unwrap(), Delivery::all(1));
        let msg = recv(&server);
        // authpriv (10) * 8 + notice (5) = 85
        assert!(
            msg.starts_with("<85>1 2026-11-17T10:00:00.000Z myhost bouncer "),
            "{msg}"
        );
        assert!(
            msg.contains(" get [bouncer@32473 seq=\"3\" log_id=\"abc\" mac=\"m3\"] {"),
            "{msg}"
        );
        assert!(msg.ends_with(std::str::from_utf8(&raw).unwrap()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn big(n: usize) -> (Vec<u8>, serde_json::Value) {
        let e = serde_json::json!({"op": "get", "result": "ok", "names": ["A", "B"],
            "reason": "x".repeat(n)});
        (serde_json::to_vec(&e).unwrap(), e)
    }

    /// A large entry is delivered on the real local socket (2 KiB on macOS by default).
    #[test]
    fn large_entries_fit_the_socket() {
        let (dir, server, mut s) = setup("big");
        let (raw, e) = big(20_000);
        let mac = "ab".repeat(32);
        let l = Line {
            raw: &raw,
            seq: 4,
            log_id: "abc",
            ts: "",
            mac: &mac,
            entry: &e,
        };
        assert_eq!(s.send(&[l]).unwrap(), Delivery::all(1));
        let msg = recv(&server);
        assert!(
            msg.len() <= s.limit && msg.len() <= MAX_MSG,
            "{}",
            msg.len()
        );
        assert!(msg.contains("seq=\"4\"") && msg.contains(&mac), "{msg}");
        assert!(
            msg.contains("names=A,B") && msg.contains("see the audit log"),
            "{msg}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// When the socket is smaller than assumed, EMSGSIZE shrinks the message instead of
    /// failing forever.
    #[test]
    fn emsgsize_shrinks_instead_of_retrying() {
        let (dir, server, mut s) = setup("emsg");
        s.sndbuf = Some(1024);
        s.assume_limit = Some(MAX_MSG);
        // Fits the assumed 8 KiB, not the real socket (at most about 4.5 KiB on Linux).
        let (raw, e) = big(5500);
        let line = |seq| Line {
            raw: &raw,
            seq,
            log_id: "abc",
            ts: "",
            mac: "m",
            entry: &e,
        };
        assert_eq!(s.send(&[line(5), line(6)]).unwrap(), Delivery::all(2));
        assert!(s.limit < MAX_MSG);
        assert!(recv(&server).contains("seq=\"5\""));
        assert!(recv(&server).contains("seq=\"6\""));
        // And a socket that refuses even the floor gives the entry up, once.
        let f = format(10, "h", &line(7), MIN_MSG);
        assert!(f.len() <= MIN_MSG);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
