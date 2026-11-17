//! Optional S3-compatible audit sink (AWS S3, Cloudflare R2, iDrive E2, MinIO, ...).
//!
//! Every audit line becomes its own object, `<prefix>/<host>/YYYY/MM/DD/<ts>-<seq>.json`, so
//! the sink never overwrites or appends and works with Object Lock (WORM) buckets.
//!
//! The local audit log doubles as the upload spool: a background thread uploads lines past a
//! byte-offset cursor (stored, fsynced, in `<audit_log>.s3cursor`) and retries with
//! exponential backoff. Requests never wait on the network.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;
use sha2::{Digest, Sha256};

use crate::audit::Notify;
use crate::config::S3Config;
use crate::err;
use crate::util::{self, Result};

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
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
    pub access_key_id: String,
    pub secret_access_key: String,
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
    let k = hmac(
        format!("AWS4{}", creds.secret_access_key).as_bytes(),
        date.as_bytes(),
    );
    let k = hmac(&k, r.region.as_bytes());
    let k = hmac(&k, r.service.as_bytes());
    let k = hmac(&k, b"aws4_request");
    let sig = util::hex(&hmac(&k, to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={sig}",
        creds.access_key_id
    )
}

/// `2026-11-17T10:00:00.123Z` -> `20261117T100000Z` (for x-amz-date).
fn amz_date(ts: &str) -> String {
    let digits: String = ts.chars().filter(char::is_ascii_digit).collect();
    format!("{}T{}Z", &digits[..8], &digits[8..14])
}

/// Object key for an audit entry.
pub fn object_key(prefix: &str, host: &str, ts: &str, seq: u64) -> String {
    let host: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_.".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    let digits: String = ts.chars().filter(char::is_ascii_digit).collect();
    let (y, m, d) = (&digits[..4], &digits[4..6], &digits[6..8]);
    let stamp = format!("{}T{}Z", &digits[..8], &digits[8..]);
    let name = format!("{host}/{y}/{m}/{d}/{stamp}-{seq:010}.json");
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
        .ok_or_else(|| err!("s3 endpoint must start with http:// or https://"))?;
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

/// Uploads one object with SigV4 auth, Content-MD5 (required by Object Lock buckets).
pub fn put_object(
    agent: &ureq::Agent,
    cfg: &S3Config,
    creds: &Credentials,
    key: &str,
    body: &[u8],
    ts: &str,
) -> Result<()> {
    let t = target(cfg, key)?;
    let payload = util::sha256_hex(body);
    let date = amz_date(ts);
    let md5 = util::base64(&Md5::digest(body));
    let headers = [
        ("content-md5", md5.clone()),
        ("host", t.host.clone()),
        ("x-amz-content-sha256", payload.clone()),
        ("x-amz-date", date.clone()),
    ];
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
    let mut resp = agent
        .put(&t.url)
        .header("host", &t.host)
        .header("content-md5", &md5)
        .header("content-type", "application/json")
        .header("x-amz-content-sha256", &payload)
        .header("x-amz-date", &date)
        .header("authorization", &auth)
        .send(body)
        .map_err(|e| err!("PUT {}: {e}", t.url))?;
    let status = resp.status().as_u16();
    if (200..300).contains(&status) {
        return Ok(());
    }
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    let snippet: String = text.chars().take(300).collect();
    Err(err!("PUT {} returned HTTP {status}: {snippet}", t.url))
}

pub type CredsFn = Box<dyn Fn() -> Option<Credentials> + Send>;

pub struct Uploader {
    pub cfg: S3Config,
    pub log: PathBuf,
    pub cursor: PathBuf,
    pub host: String,
    pub notify: Arc<Notify>,
    pub creds: CredsFn,
}

enum Stop {
    NoCredentials,
    Failed(String),
}

fn read_cursor(path: &Path) -> u64 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

impl Uploader {
    pub fn spawn(self) {
        std::thread::spawn(move || self.run());
    }

    fn run(self) {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .build()
            .into();
        let mut offset = read_cursor(&self.cursor);
        let mut backoff = Duration::from_secs(1);
        let mut warned = false;
        loop {
            let seen = self.notify.current();
            match self.upload_pending(&agent, &mut offset) {
                Ok(()) => {
                    backoff = Duration::from_secs(1);
                    warned = false;
                    self.notify.wait(seen, Duration::from_secs(60));
                }
                Err(Stop::NoCredentials) => {
                    if !warned {
                        eprintln!(
                            "bouncer: s3 sink waiting for vault secrets `{}` and `{}`",
                            self.cfg.access_key_id_secret, self.cfg.secret_access_key_secret
                        );
                        warned = true;
                    }
                    self.notify.wait(seen, Duration::from_secs(60));
                }
                Err(Stop::Failed(e)) => {
                    eprintln!("bouncer: s3 upload failed, retrying in {backoff:?}: {e}");
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(Duration::from_secs(300));
                }
            }
        }
    }

    fn upload_pending(
        &self,
        agent: &ureq::Agent,
        offset: &mut u64,
    ) -> std::result::Result<(), Stop> {
        let fail = |e: std::io::Error| Stop::Failed(format!("reading audit log: {e}"));
        let mut f = File::open(&self.log).map_err(fail)?;
        let len = f.metadata().map_err(fail)?.len();
        if *offset > len {
            eprintln!("bouncer: audit log is shorter than the s3 cursor; uploading from the start");
            *offset = 0;
        }
        if *offset == len {
            return Ok(());
        }
        let creds = (self.creds)().ok_or(Stop::NoCredentials)?;
        f.seek(SeekFrom::Start(*offset)).map_err(fail)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).map_err(fail)?;
        for line in buf.split_inclusive(|&b| b == b'\n') {
            if line.last() != Some(&b'\n') {
                break; // partial line; picked up next round
            }
            let body = &line[..line.len() - 1];
            let v: serde_json::Value = serde_json::from_slice(body)
                .map_err(|_| Stop::Failed(format!("bad audit line at byte {offset}")))?;
            let (Some(ts), Some(seq)) = (v["ts"].as_str(), v["seq"].as_u64()) else {
                return Err(Stop::Failed(format!(
                    "audit line at byte {offset} lacks ts/seq"
                )));
            };
            let key = object_key(&self.cfg.prefix, &self.host, ts, seq);
            let now = util::rfc3339_ms(util::now_ms());
            put_object(agent, &self.cfg, &creds, &key, body, &now)
                .map_err(|e| Stop::Failed(e.0))?;
            *offset += line.len() as u64;
            util::write_atomic(&self.cursor, format!("{offset}\n").as_bytes(), 0o600)
                .map_err(|e| Stop::Failed(e.0))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn example_creds() -> Credentials {
        // The documented AWS example credentials, not real ones.
        Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
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

    #[test]
    fn keys_and_targets() {
        assert_eq!(
            object_key("audit/x", "my host", "2026-11-17T09:08:07.123Z", 42),
            "audit/x/my_host/2026/11/17/20261117T090807123Z-0000000042.json"
        );
        assert_eq!(amz_date("2026-11-17T09:08:07.123Z"), "20261117T090807Z");
        let mut cfg = S3Config {
            endpoint: "https://s3.example.com:9000".into(),
            bucket: "logs".into(),
            region: "auto".into(),
            prefix: String::new(),
            path_style: true,
            access_key_id_secret: "a".into(),
            secret_access_key_secret: "b".into(),
        };
        let t = target(&cfg, "a b/c.json").unwrap();
        assert_eq!(t.url, "https://s3.example.com:9000/logs/a%20b/c.json");
        assert_eq!(t.host, "s3.example.com:9000");
        cfg.path_style = false;
        let t = target(&cfg, "k.json").unwrap();
        assert_eq!(t.url, "https://logs.s3.example.com:9000/k.json");
        assert_eq!(t.path, "/k.json");
    }
}
