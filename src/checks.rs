//! Checks of the files a daemon uses (vault, audit log, key, credentials, directories), as
//! the daemon's own uid sees them. `bouncer doctor` runs them when it runs as that uid (or
//! root); the daemon runs them for `status`, so `doctor` run by another user still gets them.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::{Config, KeySource, SecretRef, SinkKind};
use crate::util;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Note,
    Warn,
    Fail,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Check {
    pub level: Level,
    pub msg: String,
}

struct Checks {
    uid: u32,
    out: Vec<Check>,
}

impl Checks {
    fn add(&mut self, level: Level, msg: impl Into<String>) {
        self.out.push(Check {
            level,
            msg: msg.into(),
        });
    }

    /// No parent directory of `path` may be replaceable by another user.
    fn ancestors(&mut self, path: &Path) {
        let mut p = path.parent();
        while let Some(dir) = p {
            if dir.as_os_str().is_empty() {
                break;
            }
            if let Ok(m) = std::fs::metadata(dir) {
                let writable_by_others = m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0;
                let owner_ok = m.uid() == 0 || m.uid() == self.uid;
                if !owner_ok || writable_by_others {
                    self.add(
                        Level::Fail,
                        format!(
                            "{} (a parent of {}) is owned by uid {} with mode {:04o}; another user could replace what is below it",
                            dir.display(),
                            path.display(),
                            m.uid(),
                            m.mode() & 0o7777
                        ),
                    );
                    return;
                }
            }
            p = dir.parent();
        }
    }

    /// A file the daemon writes (vault, log): its owner and mode, and its directory.
    fn data(&mut self, what: &str, path: &Path) {
        match std::fs::symlink_metadata(path) {
            Err(e) => self.add(Level::Fail, format!("{what} {}: {e}", path.display())),
            Ok(m) if m.file_type().is_symlink() => self.add(
                Level::Fail,
                format!(
                    "{what} {} is a symlink; bouncer refuses to follow it",
                    path.display()
                ),
            ),
            Ok(m) => match util::check_data_file_as(&m, path, self.uid) {
                Ok(()) => self.add(
                    Level::Ok,
                    format!(
                        "{what} {} (uid {}, mode {:04o})",
                        path.display(),
                        m.uid(),
                        m.mode() & 0o7777
                    ),
                ),
                Err(e) => self.add(Level::Fail, format!("{what}: {e}")),
            },
        }
        if let Some(dir) = path.parent()
            && let Ok(m) = std::fs::symlink_metadata(dir)
            && let Err(e) = util::check_dir_as(&m, dir, true, self.uid)
        {
            self.add(Level::Fail, e.0);
        }
        self.ancestors(path);
    }

    fn secret(&mut self, what: &str, s: &SecretRef) {
        match s.path() {
            Err(_) => self.add(
                Level::Note,
                format!(
                    "{what}: {} is only readable inside the systemd unit ($CREDENTIALS_DIRECTORY is not set here)",
                    s.describe()
                ),
            ),
            Ok(p) => match std::fs::symlink_metadata(&p) {
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => self.add(
                    Level::Note,
                    format!(
                        "{what} {}: uid {} cannot inspect it (in dedicated-user mode it is read as root at start-up)",
                        p.display(),
                        self.uid
                    ),
                ),
                Err(e) => self.add(Level::Fail, format!("{what} {}: {e}", p.display())),
                Ok(m) => match util::check_secret_mode_as(
                    &m,
                    &p,
                    matches!(s, SecretRef::Credential(_)),
                    self.uid,
                ) {
                    Ok(()) => self.add(
                        Level::Ok,
                        format!("{what} {} (mode {:04o})", p.display(), m.mode() & 0o7777),
                    ),
                    Err(e) => self.add(Level::Fail, format!("{what}: {e}")),
                },
            },
        }
    }
}

/// Checks the key, vault, log and credential files for a daemon running as `uid`.
pub fn files(cfg: &Config, uid: u32) -> Vec<Check> {
    let mut c = Checks {
        uid,
        out: Vec::new(),
    };
    match &cfg.key {
        KeySource::File(p) => {
            c.secret("key file", &SecretRef::File(p.clone()));
            c.ancestors(p);
            let key_owner = std::fs::metadata(p).map(|m| m.uid()).ok();
            let vault_owner = std::fs::metadata(&cfg.vault).map(|m| m.uid()).ok();
            let owner = key_owner.unwrap_or(0);
            let callers_elsewhere = cfg.allowed_uids.iter().any(|&u| u != owner);
            if key_owner.is_some() && key_owner == vault_owner && callers_elsewhere {
                c.add(
                    Level::Note,
                    format!(
                        "the key is a file next to the vault, both readable by uid {owner}: anything that can act as that user \
                         (or root) can decrypt the vault, agents running as other uids cannot. key_credential keeps it off disk"
                    ),
                );
            } else if key_owner.is_some() && key_owner == vault_owner {
                c.add(
                    Level::Warn,
                    format!(
                        "the key and the vault are both readable by uid {owner}, which callers also run as: anything running as \
                         that user can decrypt the vault without asking bouncer. Encryption then protects only copies (backups, \
                         sync) and other users. Use dedicated-user mode (README) to keep agents away from the files"
                    ),
                );
            }
        }
        KeySource::Credential(n) => {
            c.secret("key", &SecretRef::Credential(n.clone()));
            c.add(
                Level::Note,
                format!(
                    "the key is systemd credential `{n}`. Whether it is encrypted at rest depends on the unit: \
                     LoadCredentialEncrypted= (encrypted with the host key, TPM-sealed where available) or \
                     LoadCredential= (a plain file elsewhere). doctor cannot tell which; check `systemctl cat` for the unit"
                ),
            );
        }
        KeySource::Command(a) => {
            c.add(
                Level::Note,
                format!(
                    "the key comes from `{}`, which doctor does not run; any process running as the daemon's user can usually run it too",
                    util::escape(&a.join(" "))
                ),
            );
        }
    }
    c.data("vault", &cfg.vault);
    c.data("audit log", &cfg.audit_log);
    let mut state = cfg.audit_log.clone().into_os_string();
    state.push(".state");
    c.data("audit state", Path::new(&state));
    for s in &cfg.sinks {
        let name = &s.name;
        match &s.kind {
            SinkKind::S3(k) => {
                c.secret(&format!("sink {name}: access key id"), &k.access_key_id);
                c.secret(
                    &format!("sink {name}: secret access key"),
                    &k.secret_access_key,
                );
            }
            SinkKind::Influx(k) => c.secret(&format!("sink {name}: token"), &k.token),
            SinkKind::Http(k) => {
                if let Some(h) = &k.hmac_secret {
                    c.secret(&format!("sink {name}: hmac secret"), h);
                }
            }
            SinkKind::File { path } => c.ancestors(path),
            SinkKind::Syslog(_) => {}
        }
    }
    if let Some(a) = &cfg.admission {
        c.secret("admission api key", &a.api_key);
    }
    c.out
}
