//! Webhook sink: POSTs each entry's JSON line to a URL.
//!
//! With `hmac_secret_file` (or `_credential`), each request carries
//! `X-Bouncer-Signature: sha256=<hex HMAC-SHA256(secret, body)>` so the receiver can check
//! it came from this daemon. Any 2xx status counts as delivered; redirects are not followed.

use std::time::Duration;

use zeroize::Zeroizing;

use super::{Line, Sink};
use crate::config::HttpConfig;
use crate::err;
use crate::util::{self, Result};

pub struct HttpSink {
    cfg: HttpConfig,
    secret: Option<Zeroizing<String>>,
    agent: ureq::Agent,
}

impl HttpSink {
    pub fn new(cfg: HttpConfig) -> Result<HttpSink> {
        Ok(HttpSink {
            secret: cfg.hmac_secret.as_ref().map(|s| s.load()).transpose()?,
            agent: super::agent(Duration::from_secs(30)),
            cfg,
        })
    }
}

pub fn signature(secret: &[u8], body: &[u8]) -> String {
    format!("sha256={}", util::hex(&util::hmac_sha256(secret, body)))
}

impl Sink for HttpSink {
    fn fingerprint(&self) -> String {
        format!("http:{}", self.cfg.url)
    }

    fn send(&mut self, batch: &[Line]) -> Result<usize> {
        for (i, l) in batch.iter().enumerate() {
            let mut req = self
                .agent
                .post(&self.cfg.url)
                .header("content-type", "application/json")
                .header("x-bouncer-seq", &l.seq.to_string())
                .header("x-bouncer-log-id", l.log_id);
            if let Some(s) = &self.secret {
                req = req.header("x-bouncer-signature", &signature(s.as_bytes(), l.raw));
            }
            let r = req
                .send(l.raw)
                .map_err(|e| err!("POST {}: {e}", self.cfg.url));
            let err = match r {
                Ok(resp) if (200..300).contains(&resp.status().as_u16()) => continue,
                Ok(mut resp) => err!(
                    "POST {} returned HTTP {}: {}",
                    self.cfg.url,
                    resp.status().as_u16(),
                    super::snippet(&mut resp)
                ),
                Err(e) => e,
            };
            if i > 0 {
                eprintln!("bouncer: {err}");
                return Ok(i);
            }
            return Err(err);
        }
        Ok(batch.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecretRef;
    use crate::sink::testutil::serve;
    use std::sync::Arc;

    #[test]
    fn posts_signed_entries() {
        let (port, seen) = serve(Arc::new(|r| {
            if r.headers["x-bouncer-seq"] == "2" {
                (500, "nope".into())
            } else {
                (200, String::new())
            }
        }));
        let dir = std::env::temp_dir().join(format!("bouncer-hook-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        util::Dir::secure(&dir, true).unwrap();
        let sec = dir.join("hmac");
        util::write_file_atomic(&sec, b"hook-secret", 0o600).unwrap();
        let mut s = HttpSink::new(HttpConfig {
            url: format!("http://127.0.0.1:{port}/hook"),
            hmac_secret: Some(SecretRef::File(sec)),
        })
        .unwrap();
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
        // The second entry fails: one delivered.
        assert_eq!(s.send(&[mk(1), mk(2)]).unwrap(), 1);
        assert!(s.send(&[mk(2)]).is_err());
        let r = seen.lock().unwrap()[0].clone();
        assert_eq!(r.path, "/hook");
        assert_eq!(r.body, raw);
        assert_eq!(
            r.headers["x-bouncer-signature"],
            signature(b"hook-secret", &raw)
        );
        assert_eq!(r.headers["x-bouncer-log-id"], "L");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
