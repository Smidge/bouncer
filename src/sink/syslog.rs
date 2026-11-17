//! RFC 5424 messages over the local syslog datagram socket (`/dev/log` on Linux, where
//! systemd-journald or rsyslog picks them up; `/var/run/syslog` on macOS).
//!
//! Local syslog is best effort: a full or restarting syslog daemon can drop messages after
//! the send succeeded. Use it for visibility, and an S3 or file sink for a durable copy.

use std::os::unix::net::UnixDatagram;

use super::{Line, Sink};
use crate::config::SyslogConfig;
use crate::util::{self, Result};

/// Larger messages are cut (and marked) so they fit common datagram limits.
const MAX_MSG: usize = 8 * 1024;

pub struct SyslogSink {
    cfg: SyslogConfig,
    host: String,
    sock: Option<UnixDatagram>,
}

impl SyslogSink {
    pub fn new(cfg: SyslogConfig, host: &str) -> SyslogSink {
        SyslogSink {
            cfg,
            host: sanitize(host, 255),
            sock: None,
        }
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

/// Formats one entry as an RFC 5424 message.
pub fn format(facility: u8, host: &str, l: &Line) -> Vec<u8> {
    let denied = l.entry["decision"].as_str() == Some("deny");
    let severity = if denied { 5 } else { 6 }; // notice / informational
    let pri = u32::from(facility) * 8 + severity;
    let ts = if l.ts.is_empty() { "-" } else { l.ts };
    let msgid = sanitize(l.entry["op"].as_str().unwrap_or("-"), 32);
    let mut msg = format!(
        "<{pri}>1 {ts} {host} bouncer {} {msgid} [bouncer@32473 seq=\"{}\" log_id=\"{}\"] ",
        std::process::id(),
        l.seq,
        sanitize(l.log_id, 64),
    )
    .into_bytes();
    let room = MAX_MSG.saturating_sub(msg.len());
    if l.raw.len() <= room {
        msg.extend_from_slice(l.raw);
    } else {
        let mut cut = room.saturating_sub(16);
        while cut > 0 && !std::str::from_utf8(&l.raw[..cut]).is_ok() {
            cut -= 1;
        }
        msg.extend_from_slice(&l.raw[..cut]);
        msg.extend_from_slice(b"...[truncated]");
    }
    msg
}

impl Sink for SyslogSink {
    fn fingerprint(&self) -> String {
        format!("syslog:{}", self.cfg.socket.display())
    }

    fn send(&mut self, batch: &[Line]) -> Result<usize> {
        if self.sock.is_none() {
            let s = UnixDatagram::unbound()?;
            s.connect(&self.cfg.socket).map_err(|e| {
                util::Error(format!(
                    "cannot connect to {}: {e}",
                    self.cfg.socket.display()
                ))
            })?;
            self.sock = Some(s);
        }
        let sock = self.sock.as_ref().expect("connected above");
        for (i, l) in batch.iter().enumerate() {
            if let Err(e) = sock.send(&format(self.cfg.facility, &self.host, l)) {
                self.sock = None;
                if i > 0 {
                    return Ok(i);
                }
                return Err(util::Error(format!("syslog send: {e}")));
            }
        }
        Ok(batch.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sends_rfc5424() {
        let dir = std::env::temp_dir().join(format!("bouncer-syslog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("log.sock");
        let server = UnixDatagram::bind(&path).unwrap();
        let mut s = SyslogSink::new(
            SyslogConfig {
                socket: path.clone(),
                facility: 10,
            },
            "my host",
        );
        let e = serde_json::json!({"op": "get", "decision": "deny", "seq": 3});
        let raw = serde_json::to_vec(&e).unwrap();
        let l = Line {
            raw: &raw,
            seq: 3,
            log_id: "abc",
            ts: "2026-11-17T10:00:00.000Z",
            mac: "",
            entry: &e,
        };
        assert_eq!(s.send(&[l]).unwrap(), 1);
        let mut buf = vec![0u8; 65536];
        let n = server.recv(&mut buf).unwrap();
        let msg = String::from_utf8_lossy(&buf[..n]);
        // authpriv (10) * 8 + notice (5) = 85
        assert!(
            msg.starts_with("<85>1 2026-11-17T10:00:00.000Z myhost bouncer "),
            "{msg}"
        );
        assert!(
            msg.contains(" get [bouncer@32473 seq=\"3\" log_id=\"abc\"] {"),
            "{msg}"
        );
        assert!(msg.ends_with(std::str::from_utf8(&raw).unwrap()));
        // Oversized entries are cut and marked.
        let big = serde_json::json!({"op": "get", "reason": "x".repeat(20_000)});
        let raw = serde_json::to_vec(&big).unwrap();
        let l = Line {
            raw: &raw,
            seq: 4,
            log_id: "abc",
            ts: "",
            mac: "",
            entry: &big,
        };
        let m = format(10, "h", &l);
        assert!(m.len() <= MAX_MSG && m.ends_with(b"[truncated]"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
