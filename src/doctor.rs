//! `bouncer doctor`: checks the deployment and prints actionable warnings.
//!
//! Ownership is judged against the uid the daemon runs as (`user`, else `server_uid`), not
//! the uid doctor runs as. The checks of the daemon's own files need that uid (or root);
//! run as anyone else, doctor uses the same checks as run by the daemon (`status`), or says
//! plainly that it could not make them.

use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::time::Duration;

use bouncer::checks::{self, Check, Level};
use bouncer::config::{Config, SinkKind};
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
    fn check(&mut self, c: &Check, suffix: &str) {
        let m = format!("{}{suffix}", c.msg);
        match c.level {
            Level::Ok => self.ok(m),
            Level::Note => self.note(m),
            Level::Warn => self.warn(m),
            Level::Fail => self.bad(m),
        }
    }
}

/// The uid the daemon runs as: the `user` it drops to, else `server_uid`.
fn daemon_uid(cfg: &Config) -> Result<u32> {
    match &cfg.user {
        Some(u) => bouncer::config::lookup_user(u).map(|(uid, _)| uid),
        None => Ok(cfg.server_uid),
    }
}

pub fn run(cfg: &Config) -> Result<i32> {
    let mut r = Report::default();
    let me = util::geteuid();
    println!("bouncer doctor (running as uid {me})\n\nconfig");
    let daemon = match daemon_uid(cfg) {
        Ok(u) => u,
        Err(e) => {
            r.bad(format!("cannot tell which uid the daemon runs as: {e}"));
            me
        }
    };
    r.ok(format!(
        "the daemon runs as uid {daemon}{}",
        match &cfg.user {
            Some(u) => format!(" (user = \"{}\")", escape(u)),
            None => " (server_uid)".into(),
        }
    ));
    match std::fs::metadata(&cfg.config_file) {
        Ok(m) if m.uid() != 0 && m.uid() != daemon => r.bad(format!(
            "{} is owned by uid {}; only root or the daemon's uid {daemon} should be able to change it",
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

    // Asked first: in dedicated-user mode the file checks come from here.
    let status = proto::call(
        &cfg.socket,
        cfg.server_uid,
        &Request::new(Op::Status, vec![], String::new()),
        Duration::from_secs(5),
    );

    println!("\nkey and data files");
    if me == daemon || me == 0 {
        for c in checks::files(cfg, daemon) {
            r.check(&c, "");
        }
    } else {
        match status.as_ref().ok().and_then(|s| s.status.as_ref()) {
            Some(st) if st["checks"].is_array() => {
                let list: Vec<Check> =
                    serde_json::from_value(st["checks"].clone()).unwrap_or_default();
                for c in &list {
                    r.check(c, " (checked by the daemon)");
                }
            }
            _ => r.bad(format!(
                "cannot check the key, vault and log as uid {me}, and the daemon did not report them. \
                 Run doctor as the service user (uid {daemon}), for example: \
                 sudo -u '#{daemon}' env BOUNCER_CONFIG={} bouncer doctor",
                cfg.config_file.display()
            )),
        }
    }

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
            // Callers other than the daemon's uid need group or other access.
            let mut callers: Vec<u32> = cfg
                .allowed_uids
                .iter()
                .chain(&cfg.admin_uids)
                .copied()
                .filter(|&u| u != m.uid() && u != 0)
                .collect();
            callers.sort_unstable();
            callers.dedup();
            if !callers.is_empty() && mode & 0o066 == 0 {
                r.bad(format!(
                    "uid(s) {callers:?} may connect (allowed_uids/admin_uids), but the socket's mode {mode:04o} only lets its owner in; \
                     set socket_mode = \"0660\" and socket_group"
                ));
            } else if !callers.is_empty() && mode & 0o006 == 0 {
                r.note(format!(
                    "uid(s) {callers:?} reach the socket through its group (gid {}); they must be members of it",
                    m.gid()
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
        && let Err(e) = util::check_dir_as(&m, dir, false, daemon)
        && m.uid() != 0
    {
        r.bad(e.0);
    }

    println!("\ndaemon");
    let st = match status {
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
        if st["uid"].as_u64() != Some(u64::from(daemon)) {
            r.bad(format!(
                "the daemon runs as uid {}, but the config says uid {daemon}",
                st["uid"]
            ));
        }
        if let Some(f) = st["audit"]["failed"].as_str() {
            r.bad(format!(
                "the audit log has failed: {}; run `bouncer repair` and restart",
                escape(f)
            ));
        }
        if let Some(e) = st["attribution"]["error"].as_str() {
            r.bad(escape(e));
        } else if st["attribution"]["mode"] == "helper" {
            r.ok("attribution helper is running");
        }
        for s in st["sinks"].as_array().into_iter().flatten() {
            let name = s["name"].as_str().unwrap_or("?");
            if let Some(q) = s["last_quarantined"].as_str() {
                r.warn(format!(
                    "sink {name}: {} entr(ies) refused by the destination were skipped (see `sink_reject` in the log); last: {}",
                    s["quarantined"],
                    escape(q)
                ));
            }
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
    }
    if daemon != 0 && cfg.allowed_uids.iter().all(|&u| u == daemon) {
        r.warn("the daemon and its callers share a uid (same-user mode): it is accountability, not isolation. See \"Deployment modes\" in the README");
    }

    println!("\nsinks");
    if cfg.sinks.is_empty() {
        r.warn("no sinks: the only copy of the audit log is on this host. Add an S3 (Object Lock) or file sink, or anchor `bouncer status` heads elsewhere");
    }
    for s in &cfg.sinks {
        r.ok(format!("{} ({})", s.name, s.kind.type_name()));
        match &s.kind {
            SinkKind::S3(c) => {
                if c.endpoint.starts_with("http://") {
                    r.warn(format!("  {} uses plain http", s.name));
                }
                if !c.conditional_put {
                    r.note(format!("  {}: conditional_put = false; rely on Object Lock or versioning to keep objects from being replaced", s.name));
                }
            }
            SinkKind::Http(c) if c.hmac_secret.is_none() => r.note(format!(
                "  {}: no hmac_secret, so the receiver cannot authenticate entries",
                s.name
            )),
            SinkKind::Syslog(_) => r.note(format!(
                "  {}: syslog is best effort and can drop messages",
                s.name
            )),
            _ => {}
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
