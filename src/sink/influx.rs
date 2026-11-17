//! InfluxDB v2 sink: `POST /api/v2/write` with line protocol.
//!
//! Tags: op, secret (names, comma-joined), decision, host, thread. Fields: seq, reason,
//! result, uid, pid, attribution, log_id. Timestamps are the entry's, in milliseconds.

use std::time::Duration;

use zeroize::Zeroizing;

use super::{Line, Sink};
use crate::config::InfluxConfig;
use crate::err;
use crate::util::{self, Result};

pub struct InfluxSink {
    cfg: InfluxConfig,
    host: String,
    vars: Vec<String>,
    token: Zeroizing<String>,
    agent: ureq::Agent,
}

impl InfluxSink {
    pub fn new(cfg: InfluxConfig, host: &str, vars: &[String]) -> Result<InfluxSink> {
        Ok(InfluxSink {
            token: cfg.token.load()?,
            host: host.to_string(),
            vars: vars.to_vec(),
            agent: super::agent(Duration::from_secs(30)),
            cfg,
        })
    }
}

/// Escapes a measurement name (commas, spaces).
fn esc_measurement(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            ',' | ' ' => {
                o.push('\\');
                o.push(c);
            }
            '\\' => o.push_str("\\\\"),
            '\n' | '\r' => o.push(' '),
            c => o.push(c),
        }
    }
    o
}

/// Escapes a tag key or value (commas, equals signs, spaces); newlines become spaces.
fn esc_tag(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            ',' | '=' | ' ' => {
                o.push('\\');
                o.push(c);
            }
            '\\' => o.push_str("\\\\"),
            '\n' | '\r' | '\t' => o.push_str("\\ "),
            c => o.push(c),
        }
    }
    // A tag value may not end with a backslash.
    if o.ends_with('\\') && !o.ends_with("\\\\") {
        o.pop();
    }
    o
}

/// Quotes a string field value (double quotes and backslashes escaped, newlines as `\n`).
fn str_field(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// One line of line protocol for an entry.
pub fn line_protocol(measurement: &str, host: &str, vars: &[String], l: &Line) -> String {
    let e = l.entry;
    let names: Vec<&str> = e["names"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let ctx = &e["attribution"]["context"];
    let thread = vars
        .iter()
        .find_map(|v| ctx[v.as_str()]["value"].as_str())
        .or_else(|| {
            ctx.as_object()
                .and_then(|m| m.values().next())
                .and_then(|v| v["value"].as_str())
        });
    let mut tags = vec![("op", e["op"].as_str().unwrap_or("?").to_string())];
    if !names.is_empty() {
        tags.push(("secret", names.join(",")));
    }
    if let Some(d) = e["decision"].as_str() {
        tags.push(("decision", d.to_string()));
    }
    tags.push(("host", host.to_string()));
    if let Some(t) = thread {
        tags.push(("thread", t.to_string()));
    }
    let mut out = esc_measurement(measurement);
    for (k, v) in tags {
        let v = esc_tag(&v);
        if !v.is_empty() {
            out.push_str(&format!(",{k}={v}"));
        }
    }
    let mut fields = vec![format!("seq={}i", l.seq)];
    for k in ["reason", "result", "why", "policy"] {
        if let Some(s) = e[k].as_str() {
            fields.push(format!("{k}={}", str_field(s)));
        }
    }
    if let Some(s) = e["attribution"]["status"].as_str() {
        fields.push(format!("attribution={}", str_field(s)));
    }
    for k in ["uid", "pid"] {
        if let Some(n) = e["peer"][k].as_i64() {
            fields.push(format!("{k}={n}i"));
        }
    }
    fields.push(format!("log_id={}", str_field(l.log_id)));
    out.push(' ');
    out.push_str(&fields.join(","));
    if let Some(ms) = util::parse_rfc3339_ms(l.ts) {
        out.push_str(&format!(" {ms}"));
    }
    out
}

impl Sink for InfluxSink {
    fn fingerprint(&self) -> String {
        format!(
            "influxdb:{}/{}/{}/{}",
            self.cfg.endpoint, self.cfg.org, self.cfg.bucket, self.cfg.measurement
        )
    }

    fn batch_size(&self) -> usize {
        500
    }

    fn send(&mut self, batch: &[Line]) -> Result<usize> {
        let body: Vec<String> = batch
            .iter()
            .map(|l| line_protocol(&self.cfg.measurement, &self.host, &self.vars, l))
            .collect();
        let url = format!(
            "{}/api/v2/write?org={}&bucket={}&precision=ms",
            self.cfg.endpoint,
            super::s3::uri_encode(&self.cfg.org, false),
            super::s3::uri_encode(&self.cfg.bucket, false)
        );
        let mut resp = self
            .agent
            .post(&url)
            .header(
                "authorization",
                &*Zeroizing::new(format!("Token {}", *self.token)),
            )
            .header("content-type", "text/plain; charset=utf-8")
            .send(body.join("\n").as_bytes())
            .map_err(|e| err!("POST {url}: {e}"))?;
        match resp.status().as_u16() {
            200 | 204 => Ok(batch.len()),
            s => Err(err!(
                "POST {url} returned HTTP {s}: {}",
                super::snippet(&mut resp)
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecretRef;
    use crate::sink::testutil::serve;
    use std::sync::Arc;

    #[test]
    fn escapes_line_protocol() {
        let e = serde_json::json!({
            "op": "get", "names": ["A", "b c"], "decision": "allow", "result": "ok",
            "reason": "say \"hi\"\nnext\\line", "peer": {"uid": 501, "pid": 9},
            "attribution": {"status": "ok", "context": {"T": {"value": "th=1,x", "pid": 2}}}
        });
        let raw = serde_json::to_vec(&e).unwrap();
        let l = Line {
            raw: &raw,
            seq: 7,
            log_id: "L",
            ts: "2026-11-17T10:00:00.123Z",
            mac: "",
            entry: &e,
        };
        let s = line_protocol("bouncer audit", "my,host", &["T".into()], &l);
        assert_eq!(
            s,
            "bouncer\\ audit,op=get,secret=A\\,b\\ c,decision=allow,host=my\\,host,thread=th\\=1\\,x \
             seq=7i,reason=\"say \\\"hi\\\"\\nnext\\\\line\",result=\"ok\",attribution=\"ok\",uid=501i,pid=9i,log_id=\"L\" \
             1794909600123"
        );
        assert!(!s.contains('\n'));
    }

    #[test]
    fn writes_with_token() {
        let (port, seen) = serve(Arc::new(|_| (204, String::new())));
        let dir = std::env::temp_dir().join(format!("bouncer-influx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        util::Dir::secure(&dir, true).unwrap();
        let tok = dir.join("token");
        util::write_file_atomic(&tok, b"fake-token\n", 0o600).unwrap();
        let mut s = InfluxSink::new(
            InfluxConfig {
                endpoint: format!("http://127.0.0.1:{port}"),
                org: "my org".into(),
                bucket: "audit".into(),
                token: SecretRef::File(tok),
                measurement: "bouncer_audit".into(),
            },
            "h",
            &[],
        )
        .unwrap();
        let e = serde_json::json!({"op": "ls"});
        let raw = serde_json::to_vec(&e).unwrap();
        let l = Line {
            raw: &raw,
            seq: 1,
            log_id: "L",
            ts: "",
            mac: "",
            entry: &e,
        };
        let l2 = Line {
            raw: &raw,
            seq: 2,
            log_id: "L",
            ts: "",
            mac: "",
            entry: &e,
        };
        assert_eq!(s.send(&[l, l2]).unwrap(), 2);
        let r = seen.lock().unwrap()[0].clone();
        assert_eq!(
            r.path,
            "/api/v2/write?org=my%20org&bucket=audit&precision=ms"
        );
        assert_eq!(r.headers["authorization"], "Token fake-token");
        assert_eq!(String::from_utf8(r.body).unwrap().lines().count(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
