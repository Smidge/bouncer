//! The daemon: holds the decrypted vault in memory and answers requests on a Unix socket,
//! one thread per connection. Every get/exec/set/rm is written to the audit log before the
//! response is sent; if the audit write fails, no secret is released.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::audit::{AuditLog, Entry};
use crate::config::{Config, FsyncMode};
use crate::err;
use crate::peer::{Attribution, Attributor, PeerCred, peer_cred};
use crate::policy::{Caller, Decision, Policy, PolicyInput, SecretMeta, default_policy};
use crate::proto::{
    E_BAD_REQUEST, E_DENIED, E_INTERNAL, E_NOT_FOUND, ListItem, Op, Request, Response, read_line,
};
use crate::util::{self, Result, ctx};
use crate::vault::{Key, Secret, Vault, load_key, valid_name};

const MAX_NAMES: usize = 64;
const MAX_REASON: usize = 2000;
const MAX_DESC: usize = 500;

pub struct Server {
    cfg: Config,
    key: Key,
    vault: RwLock<Vault>,
    audit: Mutex<AuditLog>,
    policy: Box<dyn Policy>,
    attributor: Attributor,
    host: String,
}

pub fn serve(cfg: Config) -> Result<()> {
    let key = load_key(&cfg.key)?;
    let vault = Vault::load(&cfg.vault, &key)?;
    let audit = AuditLog::open(&cfg.audit_log, cfg.audit_fsync == FsyncMode::Strict)?;
    let listener = bind(&cfg.socket, cfg.socket_mode)?;
    let count = vault.secrets.len();
    let server = Arc::new(Server {
        policy: default_policy(cfg.min_reason_len),
        attributor: Attributor::new(cfg.context_vars.clone(), cfg.max_chain_depth),
        host: util::hostname(),
        key,
        vault: RwLock::new(vault),
        audit: Mutex::new(audit),
        cfg,
    });
    start_s3(&server);
    eprintln!(
        "bouncer: serving {count} secret(s) on {}",
        server.cfg.socket.display()
    );
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let srv = server.clone();
                std::thread::spawn(move || srv.handle(stream));
            }
            Err(e) => eprintln!("bouncer: accept failed: {e}"),
        }
    }
    Ok(())
}

#[cfg(feature = "s3")]
fn start_s3(server: &Arc<Server>) {
    let Some(s3) = server.cfg.s3.clone() else {
        return;
    };
    let srv = server.clone();
    let (ak, sk) = (
        s3.access_key_id_secret.clone(),
        s3.secret_access_key_secret.clone(),
    );
    crate::s3::Uploader {
        log: server.cfg.audit_log.clone(),
        cursor: server.cfg.s3_cursor(),
        host: server.host.clone(),
        notify: server.audit.lock().unwrap().notify.clone(),
        creds: Box::new(move || {
            let v = srv.vault.read().unwrap();
            Some(crate::s3::Credentials {
                access_key_id: v.secrets.get(&ak)?.value.clone(),
                secret_access_key: v.secrets.get(&sk)?.value.clone(),
            })
        }),
        cfg: s3,
    }
    .spawn();
}

#[cfg(not(feature = "s3"))]
fn start_s3(server: &Arc<Server>) {
    if server.cfg.s3.is_some() {
        eprintln!("bouncer: [s3] is configured but this build has no s3 feature; ignoring");
    }
}

fn bind(path: &Path, mode: u32) -> Result<UnixListener> {
    if let Some(dir) = path.parent() {
        util::ensure_dir(dir, 0o700)?;
    }
    if path.exists() {
        if UnixStream::connect(path).is_ok() {
            return Err(err!(
                "another bouncer daemon is already listening on {}",
                path.display()
            ));
        }
        ctx(fs::remove_file(path), "cannot remove stale socket", path)?;
    }
    // Create the socket owner-only, then widen to the configured mode.
    // SAFETY: umask only swaps the process file-mode mask.
    let old = unsafe { libc::umask(0o177) };
    let listener = UnixListener::bind(path);
    // SAFETY: as above.
    unsafe { libc::umask(old) };
    let listener = ctx(listener, "cannot listen on", path)?;
    ctx(
        fs::set_permissions(path, fs::Permissions::from_mode(mode)),
        "cannot chmod",
        path,
    )?;
    Ok(listener)
}

fn bad(msg: impl Into<String>) -> Response {
    Response::fail(E_BAD_REQUEST, msg)
}

/// What an operation did, for the audit entry.
struct Outcome {
    decision: Decision,
    result: &'static str,
    policy: &'static str,
}

impl Server {
    fn handle(&self, stream: UnixStream) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
        let resp = self.process(&stream);
        let mut line = serde_json::to_vec(&resp).unwrap_or_else(|_| b"{\"ok\":false}".to_vec());
        line.push(b'\n');
        let _ = (&stream).write_all(&line);
    }

    fn process(&self, stream: &UnixStream) -> Response {
        let peer = match peer_cred(stream) {
            Ok(p) => p,
            Err(e) => return Response::fail(E_INTERNAL, format!("cannot identify caller: {e}")),
        };
        let req: Request = match read_line(stream)
            .ok()
            .and_then(|l| serde_json::from_slice(&l).ok())
        {
            Some(r) => r,
            // Never echo the parse error: a malformed `set` could contain the value.
            None => return bad("malformed request"),
        };
        if let Some(msg) = validate(&req) {
            return bad(msg);
        }
        let allowed = self.cfg.allowed_uids.contains(&peer.uid);
        match req.op {
            Op::Ls if allowed => self.list(),
            Op::Ls => Response::fail(
                E_DENIED,
                format!("uid {} may not use this daemon", peer.uid),
            ),
            Op::Get | Op::Exec => self.read(&req, peer, allowed),
            Op::Set | Op::Rm => self.write(req, peer, allowed),
        }
    }

    fn list(&self) -> Response {
        let v = self.vault.read().unwrap();
        Response {
            ok: true,
            list: v
                .secrets
                .iter()
                .map(|(name, s)| ListItem {
                    name: name.clone(),
                    desc: s.desc.clone(),
                    tags: s.tags.clone(),
                    updated: s.updated.clone(),
                })
                .collect(),
            ..Default::default()
        }
    }

    fn read(&self, req: &Request, peer: PeerCred, allowed: bool) -> Response {
        let at = self.attributor.attribute(peer.pid);
        let reason = req.reason.trim();
        let (decision, values, missing) = {
            let v = self.vault.read().unwrap();
            let found: Vec<(&String, &Secret)> = req
                .names
                .iter()
                .filter_map(|n| v.secrets.get(n).map(|s| (n, s)))
                .collect();
            let decision = if !allowed {
                Decision::Deny(format!("uid {} may not use this daemon", peer.uid))
            } else if reason.is_empty() {
                Decision::Deny("a reason is required".into())
            } else {
                self.policy.decide(&PolicyInput {
                    op: req.op,
                    secrets: found
                        .iter()
                        .map(|(n, s)| SecretMeta {
                            name: n,
                            desc: s.desc.as_deref(),
                            tags: &s.tags,
                        })
                        .collect(),
                    caller: Caller {
                        peer,
                        attribution: &at,
                    },
                    reason,
                })
            };
            let values: Vec<String> = found.iter().map(|(_, s)| s.value.clone()).collect();
            let missing: Vec<String> = req
                .names
                .iter()
                .filter(|n| !v.secrets.contains_key(*n))
                .cloned()
                .collect();
            (decision, values, missing)
        };
        let (result, resp) = match &decision {
            Decision::Deny(why) => ("denied", Response::fail(E_DENIED, why.clone())),
            Decision::Allow if !missing.is_empty() => (
                "not_found",
                Response::fail(
                    E_NOT_FOUND,
                    format!("no secret named {}", missing.join(", ")),
                ),
            ),
            _ => (
                "ok",
                Response {
                    ok: true,
                    values,
                    ..Default::default()
                },
            ),
        };
        let outcome = Outcome {
            decision,
            result,
            policy: self.policy.name(),
        };
        if let Err(e) = self.record(req, peer, &at, outcome) {
            return Response::fail(
                E_INTERNAL,
                format!("audit log write failed, refusing to release secrets: {e}"),
            );
        }
        resp
    }

    fn write(&self, req: Request, peer: PeerCred, allowed: bool) -> Response {
        let at = self.attributor.attribute(peer.pid);
        let deny = |why: String| Outcome {
            decision: Decision::Deny(why),
            result: "denied",
            policy: "writes",
        };
        let (outcome, resp) = if !allowed {
            let why = format!("uid {} may not use this daemon", peer.uid);
            (deny(why.clone()), Response::fail(E_DENIED, why))
        } else {
            match self.apply_write(&req) {
                Ok(true) => (
                    Outcome {
                        decision: Decision::Allow,
                        result: "ok",
                        policy: "writes",
                    },
                    Response {
                        ok: true,
                        ..Default::default()
                    },
                ),
                Ok(false) => (
                    Outcome {
                        decision: Decision::Allow,
                        result: "not_found",
                        policy: "writes",
                    },
                    Response::fail(E_NOT_FOUND, format!("no secret named {}", req.names[0])),
                ),
                Err(e) => (
                    Outcome {
                        decision: Decision::Allow,
                        result: "error",
                        policy: "writes",
                    },
                    Response::fail(E_INTERNAL, e.0),
                ),
            }
        };
        if let Err(e) = self.record(&req, peer, &at, outcome) {
            return Response::fail(
                E_INTERNAL,
                format!("change applied but audit write failed: {e}"),
            );
        }
        resp
    }

    /// Applies set/rm to a copy of the vault, saves it, then swaps it in.
    /// Returns false when `rm` names a missing secret.
    fn apply_write(&self, req: &Request) -> Result<bool> {
        let name = &req.names[0];
        let mut v = self.vault.write().unwrap();
        let mut next = v.clone();
        let now = util::rfc3339_ms(util::now_ms());
        if req.op == Op::Rm {
            if next.secrets.remove(name).is_none() {
                return Ok(false);
            }
        } else {
            let value = req.value.clone().unwrap_or_default();
            let created = next
                .secrets
                .get(name)
                .map(|s| s.created.clone())
                .unwrap_or_else(|| now.clone());
            let old = next.secrets.get(name);
            let desc = req
                .desc
                .clone()
                .or_else(|| old.and_then(|s| s.desc.clone()));
            let tags = if req.tags.is_empty() {
                old.map(|s| s.tags.clone()).unwrap_or_default()
            } else {
                req.tags.clone()
            };
            next.secrets.insert(
                name.clone(),
                Secret {
                    value,
                    desc,
                    tags,
                    created,
                    updated: now,
                },
            );
        }
        next.save(&self.cfg.vault, &self.key)?;
        *v = next;
        Ok(true)
    }

    fn record(&self, req: &Request, peer: PeerCred, at: &Attribution, o: Outcome) -> Result<u64> {
        let (decision, why) = match o.decision {
            Decision::Allow => ("allow", None),
            Decision::Deny(w) => ("deny", Some(w)),
        };
        let entry = Entry {
            ts: util::rfc3339_ms(util::now_ms()),
            seq: 0,
            op: req.op.as_str(),
            names: req.names.clone(),
            reason: req.reason.trim().to_string(),
            decision,
            why,
            result: o.result,
            policy: o.policy,
            host: self.host.clone(),
            peer,
            cwd: at.cwd.clone(),
            attribution: at.status,
            context: at.context.clone(),
            chain: at.chain.clone(),
            prev: String::new(),
        };
        self.audit.lock().unwrap().append(entry)
    }
}

fn validate(req: &Request) -> Option<String> {
    if req.op != Op::Ls && req.names.is_empty() {
        return Some("no secret name given".into());
    }
    if matches!(req.op, Op::Set | Op::Rm) && req.names.len() != 1 {
        return Some("set and rm take exactly one name".into());
    }
    if req.names.len() > MAX_NAMES {
        return Some(format!("at most {MAX_NAMES} names per request"));
    }
    if let Some(n) = req.names.iter().find(|n| !valid_name(n)) {
        let shown: String = n.chars().take(64).collect();
        return Some(format!(
            "invalid secret name `{shown}` (use A-Z a-z 0-9 _ . - /, max 128)"
        ));
    }
    if req.reason.chars().count() > MAX_REASON {
        return Some(format!("reason is longer than {MAX_REASON} characters"));
    }
    if req.op == Op::Set {
        if req.value.as_deref().unwrap_or("").is_empty() {
            return Some("set needs a non-empty value".into());
        }
        if req.desc.as_deref().unwrap_or("").chars().count() > MAX_DESC {
            return Some(format!("description is longer than {MAX_DESC} characters"));
        }
        if let Some(t) = req.tags.iter().find(|t| !valid_name(t)) {
            let shown: String = t.chars().take(64).collect();
            return Some(format!("invalid tag `{shown}`"));
        }
    }
    None
}
