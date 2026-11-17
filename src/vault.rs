//! The encrypted vault file and its key.
//!
//! Vault file layout (version 2):
//!
//! ```text
//! offset  size  field
//! 0       7     magic "BOUNCER"
//! 7       1     format version (2)
//! 8       8     generation, u64 little-endian; +1 on every saved change
//! 16      24    XChaCha20-Poly1305 nonce (random per write)
//! 40      n+16  ciphertext + Poly1305 tag; AAD = bytes 0..16
//! ```
//!
//! Version 1 files (8-byte header, no generation) are still read, as generation 0, and are
//! rewritten as version 2 on the next change.
//!
//! The plaintext is JSON: `{"secrets": {"NAME": {"value", "desc", "tags", "created", "updated", "rev"}}}`.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::Read;
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::config::KeySource;
use crate::err;
use crate::util::{self, Dir, Result, ctx};

const MAGIC: &[u8; 7] = b"BOUNCER";
const VERSION: u8 = 2;
const HEADER_LEN: usize = 16;
const V1_HEADER_LEN: usize = 8;
const NONCE_LEN: usize = 24;
/// Largest vault file accepted.
const MAX_VAULT: u64 = 256 << 20;

pub type Key = Zeroizing<[u8; 32]>;

#[derive(Clone, Serialize, Deserialize)]
pub struct Secret {
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub created: String,
    pub updated: String,
    /// The vault generation that last wrote this secret (0 in older vaults until the next
    /// change). Identifies the version a policy decision was made on.
    #[serde(default)]
    pub rev: u64,
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Vault {
    pub secrets: BTreeMap<String, Secret>,
    /// From the file header, not the encrypted payload.
    #[serde(skip)]
    pub generation: u64,
}

/// Secret names: 1-128 chars of `A-Z a-z 0-9 _ . - /`.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-/".contains(&b))
}

fn header(generation: u64) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..7].copy_from_slice(MAGIC);
    h[7] = VERSION;
    h[8..].copy_from_slice(&generation.to_le_bytes());
    h
}

impl Vault {
    pub fn encrypt(&self, key: &Key) -> Result<Vec<u8>> {
        self.encrypt_with_nonce(key, &util::random_bytes()?)
    }

    /// Deterministic for a given nonce; only tests pass their own.
    pub fn encrypt_with_nonce(&self, key: &Key, nonce: &[u8; NONCE_LEN]) -> Result<Vec<u8>> {
        let plain =
            Zeroizing::new(serde_json::to_vec(self).map_err(|_| err!("cannot serialise vault"))?);
        let h = header(self.generation);
        let ct = XChaCha20Poly1305::new((&**key).into())
            .encrypt(
                &XNonce::from(*nonce),
                Payload {
                    msg: &plain,
                    aad: &h,
                },
            )
            .map_err(|_| err!("encryption failed"))?;
        let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ct.len());
        out.extend_from_slice(&h);
        out.extend_from_slice(nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn decrypt(data: &[u8], key: &Key) -> Result<Vault> {
        if data.len() < 8 || &data[..7] != MAGIC {
            return Err(err!("not a bouncer vault"));
        }
        let (hlen, generation) = match data[7] {
            1 => (V1_HEADER_LEN, 0),
            2 if data.len() >= HEADER_LEN => (
                HEADER_LEN,
                u64::from_le_bytes(data[8..16].try_into().expect("length checked")),
            ),
            v => return Err(err!("unsupported vault version {v}")),
        };
        if data.len() < hlen + NONCE_LEN + 16 {
            return Err(err!("vault file is truncated"));
        }
        let nonce: [u8; NONCE_LEN] = data[hlen..hlen + NONCE_LEN]
            .try_into()
            .expect("length checked");
        let plain = Zeroizing::new(
            XChaCha20Poly1305::new((&**key).into())
                .decrypt(
                    &XNonce::from(nonce),
                    Payload {
                        msg: &data[hlen + NONCE_LEN..],
                        aad: &data[..hlen],
                    },
                )
                .map_err(|_| err!("cannot decrypt vault (wrong key or corrupted file)"))?,
        );
        // Never surface serde's message: it can quote parts of the plaintext.
        let mut v: Vault =
            serde_json::from_slice(&plain).map_err(|_| err!("vault payload is corrupt"))?;
        v.generation = generation;
        Ok(v)
    }

    /// Reads the vault file (no symlinks; owner and mode checked on the open fd). Returns
    /// the vault and the SHA-256 of the file bytes.
    pub fn load(dir: &Dir, name: &OsStr, key: &Key) -> Result<(Vault, String)> {
        let path = dir.path().join(name);
        let f = ctx(
            dir.open_at(name, libc::O_RDONLY, 0),
            "cannot open vault",
            &path,
        )?;
        util::check_data_file(&ctx(f.metadata(), "cannot stat", &path)?, &path)?;
        let mut data = Vec::new();
        ctx(
            f.take(MAX_VAULT).read_to_end(&mut data),
            "cannot read",
            &path,
        )?;
        let v = Vault::decrypt(&data, key)?;
        Ok((v, util::sha256_hex(&data)))
    }
}

/// Parses 64 hex characters (surrounding whitespace allowed) into a key.
pub fn parse_key(text: &[u8], what: &str) -> Result<Key> {
    let s = std::str::from_utf8(text).map_err(|_| err!("{what} is not text"))?;
    let bytes = Zeroizing::new(
        util::unhex(s.trim()).ok_or_else(|| err!("{what} must hold 64 hex characters"))?,
    );
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| err!("{what} must hold 64 hex characters"))?;
    Ok(Zeroizing::new(arr))
}

pub fn generate_key_hex() -> Result<Zeroizing<String>> {
    let key: Key = Zeroizing::new(util::random_bytes()?);
    Ok(Zeroizing::new(util::hex(key.as_ref())))
}

/// Creates a key file (mode 0600) in a private directory. Fails if it exists.
pub fn generate_key_file(path: &Path) -> Result<()> {
    use std::io::Write;
    let (dir, name) = util::split_path(path)?;
    let dir = Dir::secure(&dir, true)?;
    let hex = generate_key_hex()?;
    let mut f = ctx(dir.create_excl(name, 0o600), "cannot create key file", path)?;
    ctx(
        f.write_all(format!("{}\n", *hex).as_bytes()),
        "cannot write",
        path,
    )?;
    ctx(f.sync_all(), "cannot sync", path)?;
    ctx(dir.sync(), "cannot sync", dir.path())
}

pub fn load_key(src: &KeySource) -> Result<Key> {
    match src {
        KeySource::File(p) => {
            parse_key(&util::read_secret_file(p, 4096)?, &p.display().to_string())
        }
        KeySource::Credential(name) => {
            let p = crate::config::SecretRef::Credential(name.clone()).path()?;
            parse_key(
                &util::read_credential_file(&p, 4096)?,
                &p.display().to_string(),
            )
        }
        KeySource::Command(argv) => {
            let out = run_key_command(argv, KEY_COMMAND_DEADLINE)?;
            parse_key(&out, "key_command output")
        }
    }
}

/// How long `key_command` may take.
const KEY_COMMAND_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
/// The most `key_command` may print (a key is 64 hex characters).
const KEY_COMMAND_MAX_OUTPUT: u64 = 4096;

/// Runs `key_command` (no shell) in its own process group and returns its stdout. It must
/// exit successfully within `deadline` and print at most `KEY_COMMAND_MAX_OUTPUT` bytes;
/// otherwise its whole process group is killed and reaped.
fn run_key_command(argv: &[String], deadline: std::time::Duration) -> Result<Zeroizing<Vec<u8>>> {
    use std::os::unix::process::CommandExt;
    use std::time::Instant;
    let mut child = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .process_group(0)
        .spawn()
        .map_err(|e| err!("cannot run key_command `{}`: {e}", argv[0]))?;
    let pid = child.id() as libc::pid_t;
    let kill = |child: &mut std::process::Child| {
        // SAFETY: kill with a negative pid signals the process group we created.
        unsafe { libc::kill(-pid, libc::SIGKILL) };
        let _ = child.wait();
    };
    let mut stdout = child.stdout.take().expect("piped");
    let (tx, rx) = std::sync::mpsc::channel();
    // A grandchild could keep the pipe open, so the reader is never joined.
    std::thread::spawn(move || {
        let mut buf = Zeroizing::new(Vec::new());
        let r = (&mut stdout)
            .take(KEY_COMMAND_MAX_OUTPUT + 1)
            .read_to_end(&mut buf);
        let _ = tx.send(r.map(|_| buf));
    });
    let start = Instant::now();
    let fail = |child: &mut std::process::Child, why: String| {
        kill(child);
        Err(err!("key_command `{}` {why}", argv[0]))
    };
    let out = match rx.recv_timeout(deadline) {
        Ok(Ok(buf)) if buf.len() as u64 > KEY_COMMAND_MAX_OUTPUT => {
            return fail(
                &mut child,
                format!("printed more than {KEY_COMMAND_MAX_OUTPUT} bytes; killed"),
            );
        }
        Ok(Ok(buf)) => buf,
        Ok(Err(e)) => return fail(&mut child, format!("output could not be read: {e}")),
        Err(_) => {
            return fail(
                &mut child,
                format!("did not finish within {deadline:?}; killed"),
            );
        }
    };
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(out),
            Ok(Some(status)) => return Err(err!("key_command `{}` failed ({status})", argv[0])),
            Ok(None) if start.elapsed() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(5))
            }
            Ok(None) => {
                return fail(
                    &mut child,
                    format!("did not exit within {deadline:?}; killed"),
                );
            }
            Err(e) => return fail(&mut child, format!("could not be waited for: {e}")),
        }
    }
}

/// The key for the audit log's HMAC chain, derived from the vault key with a fixed label so
/// the two uses never share a key.
pub fn chain_key(key: &Key) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(util::hmac_sha256(key.as_ref(), b"bouncer audit chain v1"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vault {
        let mut v = Vault {
            generation: 7,
            ..Default::default()
        };
        v.secrets.insert(
            "A".into(),
            Secret {
                value: "fake-value".into(),
                desc: Some("d".into()),
                tags: vec!["work".into()],
                created: "t".into(),
                updated: "t".into(),
                rev: 7,
            },
        );
        v
    }

    #[test]
    fn round_trip_and_tamper_every_byte() {
        let key: Key = Zeroizing::new([7u8; 32]);
        let a = sample().encrypt(&key).unwrap();
        let b = sample().encrypt(&key).unwrap();
        assert_ne!(a, b, "nonce must be random per write");
        assert!(!a.windows(10).any(|w| w == b"fake-value"));
        let v = Vault::decrypt(&a, &key).unwrap();
        assert_eq!(v.secrets["A"].value, "fake-value");
        assert_eq!(v.generation, 7);
        assert!(Vault::decrypt(&a, &Zeroizing::new([8u8; 32])).is_err());
        // Changing any single byte (header, generation, nonce, ciphertext, tag) fails.
        for i in 0..a.len() {
            let mut t = a.clone();
            t[i] ^= 0x01;
            assert!(
                Vault::decrypt(&t, &key).is_err(),
                "byte {i} not authenticated"
            );
        }
        assert!(Vault::decrypt(&a[..a.len() - 1], &key).is_err());
    }

    /// XChaCha20-Poly1305 test vector from draft-irtf-cfrg-xchacha-03, appendix A.3.1.
    #[test]
    fn xchacha_known_answer() {
        let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
        let nonce: [u8; 24] = core::array::from_fn(|i| 0x40 + i as u8);
        let aad = util::unhex("50515253c0c1c2c3c4c5c6c7").unwrap();
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let ct = XChaCha20Poly1305::new((&key).into())
            .encrypt(&XNonce::from(nonce), Payload { msg: pt, aad: &aad })
            .unwrap();
        assert_eq!(
            util::hex(&ct),
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
             21f9664c97637da9768812f615c68b13b52e\
             c0875924c1c7987947deafd8780acf49"
        );
    }

    /// Pins the on-disk format: header, generation, nonce and AAD placement.
    #[test]
    fn vault_format_known_answer() {
        let key: Key = Zeroizing::new([0x11; 32]);
        let v = Vault {
            generation: 3,
            ..Default::default()
        };
        let out = v.encrypt_with_nonce(&key, &[0x22; 24]).unwrap();
        assert_eq!(&out[..8], b"BOUNCER\x02");
        assert_eq!(&out[8..16], &3u64.to_le_bytes());
        assert_eq!(&out[16..40], &[0x22; 24]);
        // Plaintext `{"secrets":{}}` (14 bytes) + 16-byte tag.
        assert_eq!(out.len(), 40 + 14 + 16);
        let expect = XChaCha20Poly1305::new((&*key).into())
            .encrypt(
                &XNonce::from([0x22; 24]),
                Payload {
                    msg: br#"{"secrets":{}}"#,
                    aad: &out[..16],
                },
            )
            .unwrap();
        assert_eq!(&out[40..], &expect[..]);
    }

    #[test]
    fn reads_version_1() {
        let key: Key = Zeroizing::new([5u8; 32]);
        let mut h = b"BOUNCER\x01".to_vec();
        let nonce = [9u8; 24];
        let ct = XChaCha20Poly1305::new((&*key).into())
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: br#"{"secrets":{}}"#,
                    aad: &h,
                },
            )
            .unwrap();
        h.extend_from_slice(&nonce);
        h.extend_from_slice(&ct);
        let v = Vault::decrypt(&h, &key).unwrap();
        assert_eq!(v.generation, 0);
    }

    #[test]
    fn key_command_is_bounded() {
        let sh = |script: &str| vec!["/bin/sh".to_string(), "-c".into(), script.into()];
        let key = "ab".repeat(32);
        let out = run_key_command(&sh(&format!("echo {key}")), KEY_COMMAND_DEADLINE).unwrap();
        assert_eq!(parse_key(&out, "k").unwrap()[0], 0xab);
        assert!(run_key_command(&sh("exit 3"), KEY_COMMAND_DEADLINE).is_err());
        // A command that hangs is killed (with its children) at the deadline.
        let t = std::time::Instant::now();
        let e = run_key_command(
            &sh("sleep 30 & sleep 30; echo late"),
            std::time::Duration::from_millis(300),
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("did not finish") || e.contains("did not exit"),
            "{e}"
        );
        assert!(t.elapsed() < std::time::Duration::from_secs(5));
        // Endless output is cut off at the cap.
        let e = run_key_command(&sh("yes"), KEY_COMMAND_DEADLINE)
            .unwrap_err()
            .to_string();
        assert!(e.contains("more than 4096 bytes"), "{e}");
        // Closing stdout early but running on still hits the deadline.
        let e = run_key_command(
            &sh(&format!("echo {key}; exec >&-; sleep 30")),
            std::time::Duration::from_millis(300),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("did not exit"), "{e}");
    }

    #[test]
    fn names_and_keys() {
        assert!(valid_name("GITHUB_TOKEN"));
        assert!(valid_name("work/aws.key-1"));
        assert!(!valid_name(""));
        assert!(!valid_name("a b"));
        assert!(!valid_name("x=y"));
        assert!(parse_key(b"zz", "k").is_err());
        let k = parse_key(format!("{}\n", "ab".repeat(32)).as_bytes(), "k").unwrap();
        assert_eq!(k[0], 0xab);
        assert_ne!(chain_key(&k).as_ref(), k.as_ref());
    }
}
