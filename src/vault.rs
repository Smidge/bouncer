//! The encrypted vault file and its key.
//!
//! Vault file layout (version 1):
//!
//! ```text
//! offset  size  field
//! 0       7     magic "BOUNCER"
//! 7       1     format version (1)
//! 8       24    XChaCha20-Poly1305 nonce (random per write)
//! 32      n+16  ciphertext + Poly1305 tag; AAD = bytes 0..8
//! ```
//!
//! The plaintext is JSON: `{"secrets": {"NAME": {"value", "desc", "tags", "created", "updated"}}}`.
//! The key file holds 32 random bytes as 64 hex characters and must be mode 0600.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};

use crate::err;
use crate::util::{self, Result, ctx};

const MAGIC: &[u8; 7] = b"BOUNCER";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 8;
const NONCE_LEN: usize = 24;

pub type Key = [u8; 32];

#[derive(Clone, Serialize, Deserialize)]
pub struct Secret {
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub created: String,
    pub updated: String,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Vault {
    pub secrets: BTreeMap<String, Secret>,
}

/// Secret names: 1-128 chars of `A-Z a-z 0-9 _ . - /`.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-/".contains(&b))
}

fn header() -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..7].copy_from_slice(MAGIC);
    h[7] = VERSION;
    h
}

impl Vault {
    pub fn encrypt(&self, key: &Key) -> Result<Vec<u8>> {
        let plain = serde_json::to_vec(self).map_err(|_| err!("cannot serialise vault"))?;
        let nonce_bytes: [u8; NONCE_LEN] = util::random_bytes()?;
        let cipher = XChaCha20Poly1305::new(key.into());
        let h = header();
        let ct = cipher
            .encrypt(
                &XNonce::from(nonce_bytes),
                Payload {
                    msg: &plain,
                    aad: &h,
                },
            )
            .map_err(|_| err!("encryption failed"))?;
        let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ct.len());
        out.extend_from_slice(&h);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn decrypt(data: &[u8], key: &Key) -> Result<Vault> {
        if data.len() < HEADER_LEN + NONCE_LEN + 16 || &data[..7] != MAGIC {
            return Err(err!("not a bouncer vault"));
        }
        if data[7] != VERSION {
            return Err(err!("unsupported vault version {}", data[7]));
        }
        let nonce: [u8; NONCE_LEN] = data[HEADER_LEN..HEADER_LEN + NONCE_LEN]
            .try_into()
            .expect("length checked");
        let cipher = XChaCha20Poly1305::new(key.into());
        let plain = cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &data[HEADER_LEN + NONCE_LEN..],
                    aad: &data[..HEADER_LEN],
                },
            )
            .map_err(|_| err!("cannot decrypt vault (wrong key or corrupted file)"))?;
        // Never surface serde's message: it can quote parts of the plaintext.
        serde_json::from_slice(&plain).map_err(|_| err!("vault payload is corrupt"))
    }

    pub fn load(path: &Path, key: &Key) -> Result<Vault> {
        let data = ctx(fs::read(path), "cannot read vault", path)?;
        Vault::decrypt(&data, key)
    }

    pub fn save(&self, path: &Path, key: &Key) -> Result<()> {
        util::write_atomic(path, &self.encrypt(key)?, 0o600)
    }
}

pub fn generate_key(path: &Path) -> Result<()> {
    let key: Key = util::random_bytes()?;
    util::write_atomic(path, format!("{}\n", util::hex(&key)).as_bytes(), 0o600)
}

pub fn load_key(path: &Path) -> Result<Key> {
    let meta = ctx(fs::metadata(path), "cannot read key file", path)?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(err!(
            "key file {} is accessible by other users; run: chmod 600 {}",
            path.display(),
            path.display()
        ));
    }
    let text = ctx(fs::read_to_string(path), "cannot read key file", path)?;
    util::unhex(text.trim())
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| err!("key file {} must hold 64 hex characters", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vault {
        let mut v = Vault::default();
        v.secrets.insert(
            "A".into(),
            Secret {
                value: "fake-value".into(),
                desc: Some("d".into()),
                tags: vec!["work".into()],
                created: "t".into(),
                updated: "t".into(),
            },
        );
        v
    }

    #[test]
    fn round_trip_and_tamper() {
        let key = [7u8; 32];
        let a = sample().encrypt(&key).unwrap();
        let b = sample().encrypt(&key).unwrap();
        assert_ne!(a, b, "nonce must be random per write");
        assert!(!a.windows(10).any(|w| w == b"fake-value"));
        let v = Vault::decrypt(&a, &key).unwrap();
        assert_eq!(v.secrets["A"].value, "fake-value");
        assert!(Vault::decrypt(&a, &[8u8; 32]).is_err());
        let mut t = a.clone();
        let last = t.len() - 1;
        t[last] ^= 1;
        assert!(Vault::decrypt(&t, &key).is_err());
        let mut h = a.clone();
        h[7] = 1; // same version, but flip a header byte covered by AAD
        h[0] = b'X';
        assert!(Vault::decrypt(&h, &key).is_err());
    }

    #[test]
    fn names() {
        assert!(valid_name("GITHUB_TOKEN"));
        assert!(valid_name("work/aws.key-1"));
        assert!(!valid_name(""));
        assert!(!valid_name("a b"));
        assert!(!valid_name("x=y"));
    }
}
