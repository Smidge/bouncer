//! `bouncer doctor`: checks the deployment and prints actionable warnings.

use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::time::Duration;

use bouncer::config::{Config, KeySource, SecretRef, SinkKind};
use bouncer::proto::{self, CallError, Op, Request};
use bouncer::util::{self, Result, escape};

#[derive(Default)]
struct Report {
    problems: usize,
    warnings: usize,
}

impl Report {
    fn ok(&self, msg: impl AsRef<str>) {
        println!("  ok    {}", msg.as_ref());
    }
    fn warn(&mut self, msg: impl AsRef<str>) {
        self.warnings += 1;
        println!("  WARN  {}", msg.as_ref());
    }
    fn bad(&mut self, msg: impl AsRef<str>) {
        self.problems += 1;
        println!("  FAIL  {}", msg.as_ref());
    }
    fn note(&self, msg: impl AsRef<str>) {
        println!("  note  {}", msg.as_ref());
    }
}

/// Checks that no ancestor directory of `path` can be written by another user (which would
/// let them swap the path out).
fn check_ancestors(r: &mut Report, path: &Path) {
    let me = util::geteuid();
    let mut p = path.parent();
    while let Some(dir) = p {
        if dir.as_os_str().is_empty() {
            break;
        }
        if let Ok(m) = std::fs::metadata(dir) {
            let writable_by_others = m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0;
            let owner_ok = m.uid() == 0 || m.uid() == me;
            if !owner_ok || writable_by_others {
                r.bad(format!(
                    "{} (a parent of {}) is owned by uid {} with mode {:04o}; another user could replace what is below it",
                    dir.display(),
                    path.display(),
                    m.uid(),
                    m.mode() & 0o7777
                ));
                return;
            }
        }
        p = dir.parent();
    }
}

/// A file the daemon owns (vault, log): owner, mode, and the directory around it.
fn check_data(r: &mut Report, what: &str, path: &Path) {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            r.note(format!("{what} {}: cannot inspect as uid {} (permission denied); run doctor as the daemon's user for full checks", path.display(), util::geteuid()));
            return;
        }
        Err(e) => {
            r.bad(format!("{what} {}: {e}", path.display()));
            return;
        }
        Ok(m) if m.file_type().is_symlink() => {
            r.bad(format!(
                "{what} {} is a symlink; bouncer refuses to follow it",
                path.display()
            ));
            return;
        }
        Ok(m) => match util::check_data_file(&m, path) {
            Ok(()) => r.ok(format!(
                "{what} {} (uid {}, mode {:04o})",
                path.display(),
                m.uid(),
                m.mode() & 0o7777
            )),
            Err(e) => r.bad(format!("{what}: {e}")),
        },
    }
    if let Some(dir) = path.parent()
        && let Ok(m) = std::fs::symlink_metadata(dir)
        && let Err(e) = util::check_dir(&m, dir, true)
    {
        r.bad(e.0);
    }
    check_ancestors(r, path);
}

fn check_secret(r: &mut Report, what: &str, s: &SecretRef) {
    match s.path() {
        Err(_) => r.note(format!("{what}: {} is only readable inside the systemd unit ($CREDENTIALS_DIRECTORY is not set here)", s.describe())),
        Ok(p) => match std::fs::symlink_metadata(&p) {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                r.note(format!("{what} {}: cannot inspect (permission denied)", p.display()))
            }
            Err(e) => r.bad(format!("{what} {}: {e}", p.display())),
            Ok(m) => match util::check_secret_file(&m, &p) {
                Ok(()) => r.ok(format!("{what} {} (mode {:04o})", p.display(), m.mode() & 0o7777)),
                Err(e) => r.bad(format!("{what}: {e}")),
            },
        },
    }
}

pub fn run(cfg: &Config) -> Result<i32> {
    let mut r = Report::default();
    let me = util::geteuid();
    println!("bouncer doctor (running as uid {me})\n\nconfig");
    match std::fs::metadata(&cfg.config_file) {
        Ok(m) if !util::trusted_owner(m.uid()) => r.bad(format!(
            "{} is owned by uid {}; only you or root should be able to change it",
            cfg.config_file.display(),
            m.uid()
        )),
        Ok(m) if m.mode() & 0o022 != 0 => r.bad(format!(
            "{} is writable by group or others (mode {:04o})",
            cfg.config_file.display(),
            m.mode() & 0o7777
        )),
        Ok(_) => r.ok(format!("{}", cfg.config_file.display())),
        Err(_) => r.note(format!(
            "{} does not exist; using defaults",
            cfg.config_file.display()
        )),
    }
    if cfg.allowed_uids.contains(&0) || cfg.admin_uids.contains(&0) {
        r.note("uid 0 is listed in allowed_uids/admin_uids; root can read everything anyway");
    }

    println!("\nkey");
    let same_user;
    match &cfg.key {
        KeySource::File(p) => {
            check_secret(&mut r, "key file", &SecretRef::File(p.clone()));
            check_ancestors(&mut r, p);
            let key_owner = std::fs::metadata(p).map(|m| m.uid()).ok();
            let vault_owner = std::fs::metadata(&cfg.vault).map(|m| m.uid()).ok();
            same_user = key_owner.is_some() && key_owner == vault_owner;
            if same_user {
                r.warn(format!(
                    "the key and the vault are both readable by uid {}: anything running as that user can decrypt the vault without asking bouncer. \
                     Encryption then protects only copies (backups, sync) and other users. Use dedicated-user mode \
                     (README) and/or key_credential to keep agents away from the files",
                    key_owner.unwrap_or(0)
                ));
            }
        }
        KeySource::Credential(n) => {
            same_user = false;
            check_secret(&mut r, "key", &SecretRef::Credential(n.clone()));
            r.ok("key comes from a systemd credential (not stored readable on disk)");
        }
        KeySource::Command(a) => {
            same_user = false;
            r.ok(format!(
                "key comes from `{}` (not run by doctor)",
                escape(&a.join(" "))
            ));
            r.note("any process running as the daemon's user can usually run the same command");
        }
    }
    let _ = same_user;

    println!("\ndata");
    check_data(&mut r, "vault", &cfg.vault);
    check_data(&mut r, "audit log", &cfg.audit_log);

    println!("\nsocket");
    match std::fs::symlink_metadata(&cfg.socket) {
        Ok(m) if !m.file_type().is_socket() => r.bad(format!(
            "{} exists but is not a socket",
            cfg.socket.display()
        )),
        Ok(m) => {
            let mode = m.mode() & 0o777;
            r.ok(format!(
                "{} (uid {}, gid {}, mode {:04o})",
                cfg.socket.display(),
                m.uid(),
                m.gid(),
                mode
            ));
            if mode & 0o007 != 0 {
                r.warn("the socket is accessible to all users; allowed_uids is then the only check. Prefer 0660 with socket_group");
            }
            if m.uid() != cfg.server_uid {
                r.bad(format!(
                    "the socket is owned by uid {}, but clients expect the daemon to run as uid {} (server_uid / BOUNCER_SERVER_UID)",
                    m.uid(),
                    cfg.server_uid
                ));
            }
        }
        Err(e) => r.warn(format!(
            "{}: {e} (is the daemon running?)",
            cfg.socket.display()
        )),
    }
    if let Some(dir) = cfg.socket.parent()
        && let Ok(m) = std::fs::symlink_metadata(dir)
        && let Err(e) = util::check_dir(&m, dir, false)
        && m.uid() == me
    {
        r.bad(e.0);
    }

    println!("\ndaemon");
    let st = match proto::call(
        &cfg.socket,
        cfg.server_uid,
        &Request::new(Op::Status, vec![], String::new()),
        Duration::from_secs(5),
    ) {
        Ok(resp) if resp.ok => resp.status.clone(),
        Ok(resp) => {
            r.bad(format!(
                "status failed: {}",
                escape(resp.error.as_deref().unwrap_or("?"))
            ));
            None
        }
        Err(CallError::Identity(e)) => {
            r.bad(e);
            None
        }
        Err(CallError::Unreachable(e)) => {
            r.warn(e);
            None
        }
    };
    if let Some(st) = &st {
        r.ok(format!(
            "daemon {} running as uid {}, audit head {}",
            st["version"].as_str().unwrap_or("?"),
            st["uid"],
            st["audit"]["head"].as_str().unwrap_or("?")
        ));
        if let Some(f) = st["audit"]["failed"].as_str() {
            r.bad(format!(
                "the audit log has failed: {}; run `bouncer repair` and restart",
                escape(f)
            ));
        }
        for s in st["sinks"].as_array().into_iter().flatten() {
            let name = s["name"].as_str().unwrap_or("?");
            match s["last_error"].as_str() {
                Some(e) => r.bad(format!("sink {name}: last error: {}", escape(e))),
                None if s["lag"].as_u64().unwrap_or(0) > 100 => {
                    r.warn(format!("sink {name} is {} entries behind", s["lag"]))
                }
                None => r.ok(format!(
                    "sink {name}: delivered up to seq {}",
                    s["delivered_seq"]
                )),
            }
        }
        if st["uid"].as_u64() == Some(u64::from(me)) && me != 0 {
            r.warn("the daemon runs as your own uid (same-user mode): it is accountability, not isolation. See \"Deployment modes\" in the README");
        }
    }

    println!("\nsinks");
    if cfg.sinks.is_empty() {
        r.warn("no sinks: the only copy of the audit log is on this host. Add an S3 (Object Lock) or file sink, or anchor `bouncer status` heads elsewhere");
    }
    for s in &cfg.sinks {
        r.ok(format!("{} ({})", s.name, s.kind.type_name()));
        match &s.kind {
            SinkKind::S3(c) => {
                check_secret(&mut r, "  access key id", &c.access_key_id);
                check_secret(&mut r, "  secret access key", &c.secret_access_key);
                if c.endpoint.starts_with("http://") {
                    r.warn(format!("  {} uses plain http", s.name));
                }
                if !c.conditional_put {
                    r.note(format!("  {}: conditional_put = false; rely on Object Lock or versioning to keep objects from being replaced", s.name));
                }
            }
            SinkKind::Influx(c) => check_secret(&mut r, "  token", &c.token),
            SinkKind::Http(c) => {
                if let Some(h) = &c.hmac_secret {
                    check_secret(&mut r, "  hmac secret", h);
                } else {
                    r.note(format!(
                        "  {}: no hmac_secret, so the receiver cannot authenticate entries",
                        s.name
                    ));
                }
            }
            SinkKind::File { path } => check_ancestors(&mut r, path),
            SinkKind::Syslog(_) => r.note(format!(
                "  {}: syslog is best effort and can drop messages",
                s.name
            )),
        }
    }

    println!("\nadmission");
    match &cfg.admission {
        None => r.ok("disabled (any non-empty reason of min_reason_len is enough)"),
        Some(a) => {
            r.ok(format!(
                "{:?} model {} at {}",
                a.provider,
                escape(&a.model),
                escape(&a.endpoint)
            ));
            check_secret(&mut r, "api key", &a.api_key);
            if a.on_error_allow {
                r.warn("on_error = \"allow\": secrets are released when the model is unreachable");
            }
            r.note("the admission model is a filter, not a security boundary; requesters can try to talk it round");
        }
    }

    println!();
    if r.problems > 0 {
        println!("{} problem(s), {} warning(s)", r.problems, r.warnings);
        return Ok(8);
    }
    println!("no problems, {} warning(s)", r.warnings);
    Ok(0)
}
