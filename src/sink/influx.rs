//! InfluxDB v2 sink: `POST /api/v2/write` with line protocol.
//!
//! Tags: op, secret (names, comma-joined), decision, host, thread, log_id. Fields: seq,
//! reason, result, why, policy, attribution, uid, pid, mac, prev. Every point is unique:
//! its timestamp, in nanoseconds, is the entry's millisecond time plus `seq % 1_000_000`, so
//! two entries in the same millisecond never overwrite each other, and `mac` and `prev` carry
//! the chain.
//!
//! A line the server refuses for good (HTTP 400 or 422 for that line alone, after the batch
//! is retried one line at a time) is quarantined by the runner (see `sink::run`): recorded,
//! and skipped.

use std::time::Duration;

use zeroize::Zeroizing;

use super::{Delivery, Line, Sink};
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

/// Escapes a measurement, tag key or tag value. Line protocol cannot carry control
/// characters there, so they become spaces; `special` characters (comma and space, plus `=`
/// for tags) get a backslash; a backslash is doubled, so an element never ends in a lone
/// backslash that would escape the separator after it.
fn esc(s: &str, special: &[char]) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        let c = if c.is_control() { ' ' } else { c };
        if c == '\\' {
            o.push_str("\\\\");
        } else {
            if special.contains(&c) {
                o.push('\\');
            }
            o.push(c);
        }
    }
    o
}

fn esc_measurement(s: &str) -> String {
    esc(s, &[',', ' '])
}

fn esc_tag(s: &str) -> String {
    esc(s, &[',', '=', ' '])
}

/// Quotes a string field value: `"` and `\` escaped; newlines and other control characters
/// (except tab) written as text, so a point is always one line.
fn str_field(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push('\t'),
            c if c.is_control() => o.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// The point's timestamp in nanoseconds: unique per entry of a log (see the module docs).
fn timestamp_ns(ts: &str, seq: u64) -> Option<i128> {
    let ms = util::parse_rfc3339_ms(ts)?;
    Some(i128::from(ms) * 1_000_000 + i128::from(seq % 1_000_000))
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
    tags.push(("log_id", l.log_id.to_string()));
    let mut out = esc_measurement(measurement);
    for (k, v) in tags {
        let v = esc_tag(&v);
        if !v.is_empty() {
            out.push_str(&format!(",{}={v}", esc_tag(k)));
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
    fields.push(format!("mac={}", str_field(l.mac)));
    if let Some(p) = e["prev"].as_str() {
        fields.push(format!("prev={}", str_field(p)));
    }
    out.push(' ');
    out.push_str(&fields.join(","));
    if let Some(ns) = timestamp_ns(l.ts, l.seq) {
        out.push_str(&format!(" {ns}"));
    }
    out
}

/// What one write request achieved.
enum Write {
    Ok,
    /// 400 or 422: the server will not take these lines as they are.
    Refused(String),
}

impl InfluxSink {
    fn write(&self, lines: &[String]) -> Result<Write> {
        let url = format!(
            "{}/api/v2/write?org={}&bucket={}&precision=ns",
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
            .send(lines.join("\n").as_bytes())
            .map_err(|e| err!("POST {url}: {e}"))?;
        match resp.status().as_u16() {
            200 | 204 => Ok(Write::Ok),
            s @ (400 | 422) => Ok(Write::Refused(format!(
                "HTTP {s}: {}",
                super::snippet(&mut resp)
            ))),
            s => Err(err!(
                "POST {url} returned HTTP {s}: {}",
                super::snippet(&mut resp)
            )),
        }
    }
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

    fn send(&mut self, batch: &[Line]) -> Result<Delivery> {
        let lines: Vec<String> = batch
            .iter()
            .map(|l| line_protocol(&self.cfg.measurement, &self.host, &self.vars, l))
            .collect();
        let why = match self.write(&lines)? {
            Write::Ok => return Ok(Delivery::all(batch.len())),
            Write::Refused(why) => why,
        };
        if lines.len() == 1 {
            return Ok(Delivery {
                sent: 0,
                rejected: Some(why),
            });
        }
        // Find the line it refuses: retry one at a time (rewriting a point that was already
        // written is harmless, its identity is the same).
        for (i, line) in lines.iter().enumerate() {
            match self.write(std::slice::from_ref(line)) {
                Ok(Write::Ok) => {}
                Ok(Write::Refused(why)) => {
                    return Ok(Delivery {
                        sent: i,
                        rejected: Some(why),
                    });
                }
                Err(e) if i > 0 => {
                    eprintln!("bouncer: {e}");
                    return Ok(Delivery::all(i));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(Delivery::all(batch.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecretRef;
    use crate::sink::testutil::serve;
    use std::sync::Arc;

    /// Splits a line the way InfluxDB's parser does: a backslash escapes the next byte, and
    /// unescaped spaces separate the series (measurement and tags), the fields and the time;
    /// unescaped commas separate tags. Quoted field strings may contain anything.
    fn parse(line: &str) -> (Vec<String>, String, Option<String>) {
        assert!(!line.contains('\n'), "a point must be one line: {line:?}");
        let b = line.as_bytes();
        let mut i = 0;
        let mut parts: Vec<Vec<u8>> = vec![vec![]];
        while i < b.len() && b[i] != b' ' {
            match b[i] {
                b'\\' => {
                    assert!(i + 1 < b.len(), "dangling backslash in {line:?}");
                    parts.last_mut().unwrap().push(b[i + 1]);
                    i += 2;
                    continue;
                }
                b',' => parts.push(vec![]),
                c => parts.last_mut().unwrap().push(c),
            }
            i += 1;
        }
        let series: Vec<String> = parts
            .into_iter()
            .map(|p| String::from_utf8(p).unwrap())
            .collect();
        i += 1;
        let start = i;
        let mut in_str = false;
        while i < b.len() && (in_str || b[i] != b' ') {
            match b[i] {
                b'\\' if in_str => i += 1,
                b'"' => in_str = !in_str,
                _ => {}
            }
            i += 1;
        }
        assert!(!in_str, "unterminated string in {line:?}");
        let fields = line[start..i.min(line.len())].to_string();
        let ts = (i < b.len()).then(|| line[i + 1..].to_string());
        for t in &series[1..] {
            let (k, v) = t.split_once('=').expect("tag is key=value");
            assert!(!k.is_empty() && !v.is_empty(), "{line:?}");
        }
        (series, fields, ts)
    }

    fn lp(e: &serde_json::Value, seq: u64, ts: &str) -> String {
        let raw = serde_json::to_vec(e).unwrap();
        let l = Line {
            raw: &raw,
            seq,
            log_id: "L",
            ts,
            mac: "m1",
            entry: e,
        };
        line_protocol("bouncer audit", "my,host", &["T".into()], &l)
    }

    #[test]
    fn escapes_line_protocol() {
        let e = serde_json::json!({
            "op": "get", "names": ["A", "b c"], "decision": "allow", "result": "ok",
            "reason": "say \"hi\"\nnext\\line", "peer": {"uid": 501, "pid": 9}, "prev": "p0",
            "attribution": {"status": "ok", "context": {"T": {"value": "th=1,x", "pid": 2}}}
        });
        let s = lp(&e, 7, "2026-11-17T10:00:00.123Z");
        assert_eq!(
            s,
            "bouncer\\ audit,op=get,secret=A\\,b\\ c,decision=allow,host=my\\,host,thread=th\\=1\\,x,log_id=L \
             seq=7i,reason=\"say \\\"hi\\\"\\nnext\\\\line\",result=\"ok\",attribution=\"ok\",uid=501i,pid=9i,mac=\"m1\",prev=\"p0\" \
             1794909600123000007"
        );
        parse(&s);
    }

    #[test]
    fn tricky_values_always_parse() {
        let tricky = [
            "ends with a backslash\\",
            "\\",
            "\\\\\\",
            "trailing space ",
            " ",
            "a\\,b",
            "a\\ b=c",
            "=",
            ",",
            "new\nline\r\ttab",
            "\u{1b}[31mred",
            "quote\"and\\\"",
            "emoji \u{1f600} and \u{202e}rtl",
            "",
        ];
        for (i, t) in tricky.iter().enumerate() {
            let e = serde_json::json!({
                "op": t, "names": [t, t], "decision": t, "reason": t, "why": t,
                "attribution": {"status": t, "context": {"T": {"value": t, "pid": 1}}},
            });
            let s = lp(&e, i as u64, "2026-11-17T10:00:00.123Z");
            let (series, fields, ts) = parse(&s);
            assert_eq!(series[0], "bouncer audit", "{s}");
            assert!(fields.starts_with(&format!("seq={i}i,")), "{s}");
            assert!(ts.is_some(), "{s}");
            // Every tag is still separate (a lone trailing backslash would escape the comma
            // after it and merge two tags) and decodes to the value, control characters
            // turned into spaces.
            let want: String = t
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect();
            let tags: Vec<(&str, &str)> = series[1..]
                .iter()
                .map(|t| t.split_once('=').unwrap())
                .collect();
            let keys: Vec<&str> = tags.iter().map(|t| t.0).collect();
            if want.is_empty() {
                // Empty tags are left out; two empty names still join to ",".
                assert_eq!(keys, ["secret", "host", "log_id"], "{s}");
                assert_eq!(tags[0].1, ",");
            } else {
                assert_eq!(
                    keys,
                    ["op", "secret", "decision", "host", "thread", "log_id"],
                    "{s}"
                );
                assert_eq!(tags[0].1, want, "{s}");
                assert_eq!(tags[1].1, format!("{want},{want}"), "{s}");
            }
            assert!(tags.contains(&("host", "my,host")), "{s}");
        }
    }

    #[test]
    fn points_in_the_same_millisecond_stay_distinct() {
        let e = serde_json::json!({"op": "get"});
        let ts = "2026-11-17T10:00:00.123Z";
        let stamps: std::collections::BTreeSet<String> = (1..=2000u64)
            .map(|seq| parse(&lp(&e, seq, ts)).2.unwrap())
            .collect();
        assert_eq!(stamps.len(), 2000);
        // Across a millisecond boundary too.
        let a = timestamp_ns("2026-11-17T10:00:00.123Z", 999_999).unwrap();
        let b = timestamp_ns("2026-11-17T10:00:00.124Z", 1_000_000).unwrap();
        assert!(a < b);
        let s = lp(&e, 3, ts);
        assert!(s.contains(",log_id=L ") && s.contains("mac=\"m1\""), "{s}");
    }

    fn sink(port: u16, dir: &std::path::Path) -> InfluxSink {
        let tok = dir.join("token");
        util::write_file_atomic(&tok, b"fake-token\n", 0o600).unwrap();
        InfluxSink::new(
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
        .unwrap()
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bouncer-influx-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        util::Dir::secure(&dir, true).unwrap();
        dir
    }

    #[test]
    fn writes_with_token() {
        let (port, seen) = serve(Arc::new(|_| (204, String::new())));
        let dir = tmp("w");
        let mut s = sink(port, &dir);
        let e = serde_json::json!({"op": "ls"});
        let raw = serde_json::to_vec(&e).unwrap();
        let mk = |seq| Line {
            raw: &raw,
            seq,
            log_id: "L",
            ts: "",
            mac: "",
            entry: &e,
        };
        assert_eq!(s.send(&[mk(1), mk(2)]).unwrap(), Delivery::all(2));
        let r = seen.lock().unwrap()[0].clone();
        assert_eq!(
            r.path,
            "/api/v2/write?org=my%20org&bucket=audit&precision=ns"
        );
        assert_eq!(r.headers["authorization"], "Token fake-token");
        assert_eq!(String::from_utf8(r.body).unwrap().lines().count(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_refused_line_is_reported_not_retried_forever() {
        // The server refuses any request containing seq=2.
        let (port, _) = serve(Arc::new(|r| {
            if String::from_utf8_lossy(&r.body).contains("seq=2i") {
                (
                    400,
                    "{\"code\":\"invalid\",\"message\":\"unable to parse\"}".into(),
                )
            } else {
                (204, String::new())
            }
        }));
        let dir = tmp("r");
        let mut s = sink(port, &dir);
        let e = serde_json::json!({"op": "get"});
        let raw = serde_json::to_vec(&e).unwrap();
        let mk = |seq| Line {
            raw: &raw,
            seq,
            log_id: "L",
            ts: "",
            mac: "",
            entry: &e,
        };
        let d = s.send(&[mk(1), mk(2), mk(3)]).unwrap();
        assert_eq!(d.sent, 1);
        assert!(d.rejected.unwrap().contains("HTTP 400"));
        // The runner skips seq 2 and carries on with 3.
        assert_eq!(s.send(&[mk(3)]).unwrap(), Delivery::all(1));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
