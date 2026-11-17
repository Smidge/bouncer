//! S3-compatible audit sink (AWS S3, Cloudflare R2, iDrive E2, MinIO, ...).
//!
//! Every audit line becomes its own object,
//! `<prefix>/<host>/YYYY/MM/DD/<log_id>-<seq>-<mac>.json`. The key names the entry's content
//! (its MAC), and uploads send `If-None-Match: *`, so an existing object is never replaced
//! (where the provider supports conditional writes). A 412 means an object with that key
//! exists; before counting the entry as delivered, the sink compares the object's ETag with
//! the MD5 of the entry (when the ETag is a plain MD5 and HEAD is allowed). A different
//! object is a conflict: the entry is not acknowledged and the sink reports the error.
//! Requests are signed with AWS SigV4 and carry `Content-MD5`, which Object Lock requires.

use std::time::Duration;

use md5::{Digest, Md5};
use zeroize::Zeroizing;

use super::{Delivery, Line, Sink};
use crate::config::S3Config;
use crate::err;
use crate::util::{self, Result};

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    util::hmac_sha256(key, data).to_vec()
}

/// Percent-encodes per SigV4 rules; `/` is kept when encoding a path.
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) || (keep_slash && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub struct Credentials {
    pub access_key_id: Zeroizing<String>,
    pub secret_access_key: Zeroizing<String>,
}

/// Inputs to an AWS Signature Version 4 signature.
pub struct SignRequest<'a> {
    pub method: &'a str,
    /// URI-encoded absolute path.
    pub path: &'a str,
    /// Canonical query string (empty for none).
    pub query: &'a str,
    /// Headers to sign; names must be lowercase.
    pub headers: &'a [(&'a str, String)],
    pub payload_sha256: &'a str,
    pub region: &'a str,
    pub service: &'a str,
    /// `YYYYMMDDTHHMMSSZ`.
    pub amz_date: &'a str,
}

/// Returns the `Authorization` header value.
pub fn authorization(r: &SignRequest, creds: &Credentials) -> String {
    let mut headers: Vec<_> = r.headers.iter().collect();
    headers.sort_by(|a, b| a.0.cmp(b.0));
    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{k}:{}\n", v.trim()))
        .collect();
    let signed: Vec<&str> = headers.iter().map(|(k, _)| *k).collect();
    let signed = signed.join(";");
    let canonical = format!(
        "{}\n{}\n{}\n{canonical_headers}\n{signed}\n{}",
        r.method, r.path, r.query, r.payload_sha256
    );
    let date = &r.amz_date[..8];
    let scope = format!("{date}/{}/{}/aws4_request", r.region, r.service);
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{scope}\n{}",
        r.amz_date,
        util::sha256_hex(canonical.as_bytes())
    );
    // Each derived key is as good as the secret for a day, so all are wiped.
    let k = Zeroizing::new(hmac(
        Zeroizing::new(format!("AWS4{}", *creds.secret_access_key)).as_bytes(),
        date.as_bytes(),
    ));
    let k = Zeroizing::new(hmac(&k, r.region.as_bytes()));
    let k = Zeroizing::new(hmac(&k, r.service.as_bytes()));
    let k = Zeroizing::new(hmac(&k, b"aws4_request"));
    let sig = util::hex(&hmac(&k, to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={sig}",
        *creds.access_key_id
    )
}

/// `2026-11-17T10:00:00.123Z` -> `20261117T100000Z` (for x-amz-date).
pub fn amz_date(ms: i64) -> String {
    let ts = util::rfc3339_ms(ms);
    let d: String = ts.chars().filter(char::is_ascii_digit).collect();
    format!("{}T{}Z", &d[..8], &d[8..14])
}

/// Object key for an audit entry: unique per (log_id, seq) and naming its content (the MAC),
/// grouped by host and date.
pub fn object_key(prefix: &str, host: &str, ts: &str, log_id: &str, seq: u64, mac: &str) -> String {
    let clean = |s: &str, max: usize| -> String {
        s.chars()
            .take(max)
            .map(|c| {
                if c.is_ascii_alphanumeric() || "-_.".contains(c) {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    };
    let date = match util::parse_rfc3339_ms(ts) {
        Some(_) => format!("{}/{}/{}", &ts[..4], &ts[5..7], &ts[8..10]),
        None => "undated".into(),
    };
    let name = format!(
        "{}/{date}/{}-{seq:012}-{}.json",
        clean(host, 64),
        clean(log_id, 64),
        clean(mac, 64)
    );
    if prefix.is_empty() {
        name
    } else {
        format!("{prefix}/{name}")
    }
}

struct Target {
    url: String,
    host: String,
    path: String,
}

fn target(cfg: &S3Config, key: &str) -> Result<Target> {
    let (scheme, rest) = cfg
        .endpoint
        .split_once("://")
        .ok_or_else(|| err!("s3 endpoint must start with https://"))?;
    let (host, base) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].trim_end_matches('/')),
        None => (rest, ""),
    };
    let key = uri_encode(key, true);
    let bucket = uri_encode(&cfg.bucket, false);
    let (host, path) = if cfg.path_style {
        (host.to_string(), format!("{base}/{bucket}/{key}"))
    } else {
        (format!("{bucket}.{host}"), format!("{base}/{key}"))
    };
    Ok(Target {
        url: format!("{scheme}://{host}{path}"),
        host,
        path,
    })
}

/// What a PUT achieved.
#[derive(Debug, PartialEq)]
pub enum Put {
    Created,
    /// 412: an object with this key exists. It should be this entry, uploaded before the
    /// cursor was saved; `send` checks that before counting it as delivered.
    Exists,
}

/// The ETag S3 gives a single-part upload without SSE-KMS: the hex MD5 of the body.
pub fn etag(body: &[u8]) -> String {
    util::hex(&Md5::digest(body))
}

/// The ETag of an existing object, or None if HEAD is not allowed (the key lacks
/// s3:GetObject) or the answer has no ETag.
pub fn head_etag(
    agent: &ureq::Agent,
    cfg: &S3Config,
    creds: &Credentials,
    key: &str,
    now_ms: i64,
) -> Result<Option<String>> {
    let t = target(cfg, key)?;
    let payload = util::sha256_hex(b"");
    let date = amz_date(now_ms);
    let headers = vec![
        ("host", t.host.clone()),
        ("x-amz-content-sha256", payload.clone()),
        ("x-amz-date", date.clone()),
    ];
    let auth = authorization(
        &SignRequest {
            method: "HEAD",
            path: &t.path,
            query: "",
            headers: &headers,
            payload_sha256: &payload,
            region: &cfg.region,
            service: "s3",
            amz_date: &date,
        },
        creds,
    );
    let mut req = agent.head(&t.url);
    for (k, v) in &headers {
        req = req.header(*k, v);
    }
    let resp = req
        .header("authorization", &auth)
        .call()
        .map_err(|e| err!("HEAD {}: {e}", t.url))?;
    match resp.status().as_u16() {
        200 => Ok(resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().trim_matches('"').to_ascii_lowercase())),
        401 | 403 => Ok(None),
        s => Err(err!(
            "HEAD {} returned HTTP {s} after the PUT said the object exists",
            t.url
        )),
    }
}

/// Uploads one object with SigV4 auth and Content-MD5. Only 200 and 201 count as success.
pub fn put_object(
    agent: &ureq::Agent,
    cfg: &S3Config,
    creds: &Credentials,
    key: &str,
    body: &[u8],
    now_ms: i64,
) -> Result<Put> {
    let t = target(cfg, key)?;
    let payload = util::sha256_hex(body);
    let date = amz_date(now_ms);
    let md5 = util::base64(&Md5::digest(body));
    let mut headers = vec![
        ("content-md5", md5.clone()),
        ("host", t.host.clone()),
        ("x-amz-content-sha256", payload.clone()),
        ("x-amz-date", date.clone()),
    ];
    if cfg.conditional_put {
        headers.insert(1, ("if-none-match", "*".to_string()));
    }
    let auth = authorization(
        &SignRequest {
            method: "PUT",
            path: &t.path,
            query: "",
            headers: &headers,
            payload_sha256: &payload,
            region: &cfg.region,
            service: "s3",
            amz_date: &date,
        },
        creds,
    );
    let mut req = agent.put(&t.url).header("content-type", "application/json");
    for (k, v) in &headers {
        req = req.header(*k, v);
    }
    let mut resp = req
        .header("authorization", &auth)
        .send(body)
        .map_err(|e| err!("PUT {}: {e}", t.url))?;
    let status = resp.status().as_u16();
    match status {
        200 | 201 => Ok(Put::Created),
        412 if cfg.conditional_put => Ok(Put::Exists),
        400 | 501 if cfg.conditional_put => {
            let text = super::snippet(&mut resp);
            Err(err!(
                "PUT {} returned HTTP {status}: {text}. If this provider does not support conditional writes \
                 (If-None-Match), set conditional_put = false for this sink",
                t.url
            ))
        }
        _ => {
            let text = super::snippet(&mut resp);
            Err(err!("PUT {} returned HTTP {status}: {text}", t.url))
        }
    }
}

pub struct S3Sink {
    cfg: S3Config,
    host: String,
    creds: Credentials,
    agent: ureq::Agent,
    pub existing: u64,
}

impl S3Sink {
    pub fn new(cfg: S3Config, host: &str) -> Result<S3Sink> {
        let creds = Credentials {
            access_key_id: cfg.access_key_id.load()?,
            secret_access_key: cfg.secret_access_key.load()?,
        };
        Ok(S3Sink {
            host: host.to_string(),
            creds,
            agent: super::agent(Duration::from_secs(30)),
            existing: 0,
            cfg,
        })
    }
}

impl S3Sink {
    /// After a 412: the object at this entry's key must be this entry.
    fn check_existing(&mut self, key: &str, body: &[u8]) -> Result<()> {
        let want = etag(body);
        let got = head_etag(&self.agent, &self.cfg, &self.creds, key, util::now_ms())?;
        // An ETag that is not a plain MD5 (multipart, SSE-KMS), or none visible: the key names
        // the entry's MAC, which only this daemon can produce, so it is taken as this entry.
        if let Some(tag) = got
            && tag.len() == 32
            && tag.bytes().all(|b| b.is_ascii_hexdigit())
            && tag != want
        {
            return Err(err!(
                "an object already exists at {key} with different content (ETag {tag}, \
                 expected {want}); this entry was not acknowledged. Something else wrote \
                 to this key: check the bucket"
            ));
        }
        self.existing += 1;
        Ok(())
    }
}

impl Sink for S3Sink {
    fn fingerprint(&self) -> String {
        format!(
            "s3:{}/{}/{}",
            self.cfg.endpoint, self.cfg.bucket, self.cfg.prefix
        )
    }

    fn send(&mut self, batch: &[Line]) -> Result<Delivery> {
        for (i, l) in batch.iter().enumerate() {
            let key = object_key(&self.cfg.prefix, &self.host, l.ts, l.log_id, l.seq, l.mac);
            let r = put_object(
                &self.agent,
                &self.cfg,
                &self.creds,
                &key,
                l.raw,
                util::now_ms(),
            )
            .and_then(|p| match p {
                Put::Created => Ok(()),
                Put::Exists => self.check_existing(&key, l.raw),
            });
            match r {
                Ok(()) => {}
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

    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn example_creds() -> Credentials {
        // The documented AWS example credentials, not real ones.
        Credentials {
            access_key_id: Zeroizing::new("AKIAIOSFODNN7EXAMPLE".into()),
            secret_access_key: Zeroizing::new("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into()),
        }
    }

    /// AWS SigV4 S3 documentation example "GET Object".
    #[test]
    fn sigv4_get_object_vector() {
        let headers = [
            ("host", "examplebucket.s3.amazonaws.com".to_string()),
            ("range", "bytes=0-9".to_string()),
            ("x-amz-content-sha256", EMPTY.to_string()),
            ("x-amz-date", "20130524T000000Z".to_string()),
        ];
        let auth = authorization(
            &SignRequest {
                method: "GET",
                path: "/test.txt",
                query: "",
                headers: &headers,
                payload_sha256: EMPTY,
                region: "us-east-1",
                service: "s3",
                amz_date: "20130524T000000Z",
            },
            &example_creds(),
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    /// AWS SigV4 S3 documentation example "PUT Object".
    #[test]
    fn sigv4_put_object_vector() {
        let body = b"Welcome to Amazon S3.";
        let payload = util::sha256_hex(body);
        assert_eq!(
            payload,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        let headers = [
            ("date", "Fri, 24 May 2013 00:00:00 GMT".to_string()),
            ("host", "examplebucket.s3.amazonaws.com".to_string()),
            ("x-amz-content-sha256", payload.clone()),
            ("x-amz-date", "20130524T000000Z".to_string()),
            ("x-amz-storage-class", "REDUCED_REDUNDANCY".to_string()),
        ];
        let auth = authorization(
            &SignRequest {
                method: "PUT",
                path: &format!("/{}", uri_encode("test$file.text", true)),
                query: "",
                headers: &headers,
                payload_sha256: &payload,
                region: "us-east-1",
                service: "s3",
                amz_date: "20130524T000000Z",
            },
            &example_creds(),
        );
        assert!(
            auth.ends_with(
                "Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
            ),
            "{auth}"
        );
    }

    fn cfg(endpoint: String) -> S3Config {
        S3Config {
            endpoint,
            bucket: "logs".into(),
            region: "auto".into(),
            prefix: String::new(),
            path_style: true,
            access_key_id: SecretRef::File("/nonexistent".into()),
            secret_access_key: SecretRef::File("/nonexistent".into()),
            conditional_put: true,
        }
    }

    #[test]
    fn keys_and_targets() {
        assert_eq!(
            object_key(
                "audit/x",
                "my host",
                "2026-11-17T09:08:07.123Z",
                "ab12",
                42,
                "c0ffee"
            ),
            "audit/x/my_host/2026/11/17/ab12-000000000042-c0ffee.json"
        );
        // Odd timestamps never panic.
        assert_eq!(
            object_key("", "h", "2026", "L", 1, "m"),
            "h/undated/L-000000000001-m.json"
        );
        assert_eq!(
            object_key("", "h", "", "../x", 1, "/m"),
            "h/undated/.._x-000000000001-_m.json"
        );
        assert_eq!(amz_date(1_795_000_000_000), "20261118T110640Z");
        let mut cfg = cfg("https://s3.example.com:9000".into());
        let t = target(&cfg, "a b/c.json").unwrap();
        assert_eq!(t.url, "https://s3.example.com:9000/logs/a%20b/c.json");
        assert_eq!(t.host, "s3.example.com:9000");
        cfg.path_style = false;
        let t = target(&cfg, "k.json").unwrap();
        assert_eq!(t.url, "https://logs.s3.example.com:9000/k.json");
        assert_eq!(t.path, "/k.json");
    }

    #[test]
    fn conditional_put_and_status_codes() {
        use crate::sink::testutil::serve;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU16, Ordering};
        let next = Arc::new(AtomicU16::new(200));
        let n2 = next.clone();
        let (port, seen) = serve(Arc::new(move |_| {
            (n2.load(Ordering::SeqCst), String::new())
        }));
        let mut c = cfg(format!("http://127.0.0.1:{port}"));
        let agent = super::super::agent(Duration::from_secs(5));
        let put = |c: &S3Config| put_object(&agent, c, &example_creds(), "k.json", b"{}", 0);
        assert_eq!(put(&c).unwrap(), Put::Created);
        let r = seen.lock().unwrap().last().unwrap().clone();
        assert_eq!(r.headers["if-none-match"], "*");
        assert!(
            r.headers["authorization"].contains("SignedHeaders=content-md5;host;if-none-match;")
        );
        next.store(412, Ordering::SeqCst);
        assert_eq!(put(&c).unwrap(), Put::Exists);
        // 204 and redirects are not success.
        next.store(204, Ordering::SeqCst);
        assert!(put(&c).is_err());
        next.store(301, Ordering::SeqCst);
        assert!(put(&c).is_err());
        next.store(501, Ordering::SeqCst);
        assert!(
            put(&c)
                .unwrap_err()
                .to_string()
                .contains("conditional_put = false")
        );
        c.conditional_put = false;
        next.store(200, Ordering::SeqCst);
        put(&c).unwrap();
        assert!(
            !seen
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .headers
                .contains_key("if-none-match")
        );
    }

    /// A 412 is only counted as delivered when the existing object is this entry.
    #[test]
    fn existing_object_must_be_this_entry() {
        use crate::sink::testutil::serve_with_headers;
        use std::sync::{Arc, Mutex};
        let body = br#"{"seq":1,"mac":"m"}"#.to_vec();
        // What HEAD answers: (status, etag).
        let head = Arc::new(Mutex::new((200u16, etag(&body))));
        let h2 = head.clone();
        let (port, seen) = serve_with_headers(Arc::new(move |r| {
            if r.method == "PUT" {
                return (412, vec![], String::new());
            }
            let (status, tag) = h2.lock().unwrap().clone();
            (
                status,
                vec![("ETag".into(), format!("\"{tag}\""))],
                String::new(),
            )
        }));
        let dir = std::env::temp_dir().join(format!("bouncer-s3c-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        util::Dir::secure(&dir, true).unwrap();
        for f in ["ak", "sk"] {
            util::write_file_atomic(&dir.join(f), b"fake-credential", 0o600).unwrap();
        }
        let mut c = cfg(format!("http://127.0.0.1:{port}"));
        c.access_key_id = SecretRef::File(dir.join("ak"));
        c.secret_access_key = SecretRef::File(dir.join("sk"));
        let mut sink = S3Sink::new(c, "h").unwrap();
        let e = serde_json::json!({});
        let mac = "ab".repeat(32);
        let line = Line {
            raw: &body,
            seq: 1,
            log_id: "L",
            ts: "2026-11-17T09:08:07.123Z",
            mac: &mac,
            entry: &e,
        };
        // Same content: delivered, after a signed HEAD of the same key.
        assert_eq!(sink.send(&[line]).unwrap(), Delivery::all(1));
        let reqs = seen.lock().unwrap().clone();
        assert_eq!(reqs[1].method, "HEAD");
        assert_eq!(reqs[1].path, reqs[0].path);
        assert!(reqs[0].path.ends_with(&format!("-000000000001-{mac}.json")));
        assert!(reqs[1].headers["authorization"].starts_with("AWS4-HMAC-SHA256 "));
        // Different content: a conflict, never acknowledged.
        *head.lock().unwrap() = (200, etag(b"something else"));
        let e = sink.send(&[line]).unwrap_err().to_string();
        assert!(e.contains("different content"), "{e}");
        // HEAD not allowed, or an ETag that is not an MD5: the content-addressed key decides.
        *head.lock().unwrap() = (403, String::new());
        assert_eq!(sink.send(&[line]).unwrap(), Delivery::all(1));
        *head.lock().unwrap() = (200, "0123-4".into());
        assert_eq!(sink.send(&[line]).unwrap(), Delivery::all(1));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
