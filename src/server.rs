//! The daemon: holds the decrypted vault in memory and answers requests on a Unix socket.
//!
//! Per connection: the peer's uid is checked right after accept, and connections from other
//! uids are closed before anything is read. Then the caller is attributed (before the
//! request is read, so it cannot exit or exec first), the request is read against one
//! deadline, decided, written to the audit log, and only then answered. If the audit write
//! fails, nothing is released and the daemon stays in a failed state until repaired.
//!
//! Mutations are serialised: the audit entry (with a transaction id, the new vault
//! generation and the new file's hash) is written first, then the vault file, then the
//! in-memory copy is swapped. If saving fails, an `abort` entry records it and the in-memory
//! vault is unchanged, so readers never see a change that is not in the log.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::time::{Duration, Instant};

use crate::audit::{self, AuditLog, Entry, VaultState};
use crate::config::{Config, FsyncMode};
use crate::err;
use crate::peer::{Attribution, Attributor, Caller, PeerCred};
use crate::policy::{self, Decision, Policy, PolicyInput, SecretMeta, Verdict};
use crate::proto::{
    self, E_AUDIT, E_BAD_REQUEST, E_BUSY, E_DENIED, E_INTERNAL, E_NOT_FOUND, E_VERIFY, ListItem,
    MAX_DESC, MAX_NAMES, MAX_REASON, MAX_TAGS, Op, Request, Response, SecretValue,
};
use crate::sink::{self, StatusHandle};
use crate::util::{self, Dir, Result, WriteError, ctx};
use crate::vault::{self, Key, Secret, Vault, valid_name};

const WORKER_STACK: usize = 512 * 1024;
const REJECT_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// What a read decision was made on: a secret's metadata and version, never its value.
struct Meta {
    name: String,
    desc: Option<String>,
    tags: Vec<String>,
    rev: u64,
}

enum Outcome {
    Denied,
    Missing(Vec<String>),
    /// A secret changed again after the decision was re-made.
    Changed,
    Release(Vec<SecretValue>),
}

/// The size of a value's JSON encoding plus a newline, without making a copy of it.
fn encoded_len(resp: &impl serde::Serialize) -> usize {
    struct Count(usize);
    impl Write for Count {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0 += b.len();
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut c = Count(0);
    match serde_json::to_writer(&mut c, resp) {
        Ok(()) => c.0 + 1,
        Err(_) => usize::MAX,
    }
}

#[derive(Default)]
pub struct Options {
    /// Start even if the vault does not match the audit log (recorded in the log).
    pub accept_vault_mismatch: bool,
}

enum AttrSource {
    Local(Attributor),
    #[cfg(target_os = "linux")]
    Inspector(crate::privsep::Inspector),
}

#[derive(Default)]
struct Rejects {
    count: u64,
    uids: BTreeSet<u32>,
    last_logged: Option<Instant>,
}

struct Job {
    stream: UnixStream,
    caller: Caller,
    admin_socket: bool,
}

pub struct Server {
    cfg: Config,
    key: Key,
    vault: RwLock<Vault>,
    vault_dir: Dir,
    vault_name: OsString,
    audit: Mutex<AuditLog>,
    shared: Arc<audit::Shared>,
    write_lock: Mutex<()>,
    base: Box<dyn Policy>,
    admission: Option<Box<dyn Policy>>,
    attr: AttrSource,
    host: String,
    rejects: Mutex<Rejects>,
    rejected_total: AtomicU64,
    sinks: Vec<StatusHandle>,
    started: String,
    inflight: AtomicUsize,
    pool: Pool<Job>,
    /// Test hook: the directory fsync after the vault rename fails.
    #[cfg(test)]
    fail_dir_sync: std::sync::atomic::AtomicBool,
    _lock: File,
}

/// Takes the store's exclusive lock (`bouncer.lock` next to the vault) for as long as the
/// returned file is open. A second daemon, `init` or `repair` on the same store fails.
pub fn lock_store(cfg: &Config) -> Result<File> {
    let (dir, _) = util::split_path(&cfg.vault)?;
    let dir = Dir::secure(&dir, true)?;
    let path = cfg.lock_path();
    let f = ctx(
        dir.open_at("bouncer.lock".as_ref(), libc::O_RDWR | libc::O_CREAT, 0o600),
        "cannot open lock file",
        &path,
    )?;
    util::check_data_file(&f.metadata()?, &path)?;
    // SAFETY: flock on an fd we own.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(err!(
            "another bouncer process (daemon, init or repair) is using the store in {}",
            dir.path().display()
        ));
    }
    Ok(f)
}

/// Binds a socket in a verified directory. An existing path is only removed if it is a
/// socket owned by us that nobody is listening on.
fn bind(path: &Path, mode: u32, group: Option<u32>) -> Result<UnixListener> {
    let (dir, name) = util::split_path(path)?;
    let d = Dir::secure(&dir, false)?;
    if let Some(st) = d.lstat(name)? {
        #[allow(clippy::unnecessary_cast)] // mode_t is u16 on macOS, u32 on Linux
        let is_sock = (st.st_mode as u32 & libc::S_IFMT as u32) == libc::S_IFSOCK as u32;
        if !is_sock || st.st_uid != util::geteuid() {
            return Err(err!(
                "{} exists and is not a socket owned by uid {}; refusing to remove it",
                path.display(),
                util::geteuid()
            ));
        }
        if UnixStream::connect(path).is_ok() {
            return Err(err!(
                "another bouncer daemon is already listening on {}",
                path.display()
            ));
        }
        ctx(d.unlink(name), "cannot remove stale socket", path)?;
    }
    // The socket is created with 0777 & ~umask, so set the umask to give exactly `mode`.
    // No other thread creates files at this point.
    // SAFETY: umask only swaps the process file-mode mask.
    let old = unsafe { libc::umask((0o777 & !mode) as libc::mode_t) };
    let listener = UnixListener::bind(path);
    // SAFETY: as above.
    unsafe { libc::umask(old) };
    let listener = ctx(listener, "cannot listen on", path)?;
    if let Some(g) = group {
        ctx(
            d.chown(name, None, Some(g)),
            "cannot set the socket's group",
            path,
        )?;
    }
    Ok(listener)
}

/// Prepares a socket directory while still root (dedicated-user mode): creates it if
/// needed and hands it to the daemon user.
#[cfg(target_os = "linux")]
fn prepare_socket_dir(path: &Path, uid: u32, group: Option<u32>) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    let (dir, _) = util::split_path(path)?;
    if std::fs::symlink_metadata(&dir).is_err() {
        ctx(
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir),
            "cannot create",
            &dir,
        )?;
    }
    let f = ctx(
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&dir),
        "cannot open",
        &dir,
    )?;
    let m = f.metadata()?;
    if m.uid() != 0 && m.uid() != uid {
        return Err(err!(
            "{} is owned by uid {}; refusing to use it",
            dir.display(),
            m.uid()
        ));
    }
    let mode = if group.is_some() { 0o710 } else { 0o700 };
    // chmod while still the owner (no CAP_FOWNER needed), then hand it over.
    // SAFETY: fchmod/fchown on an fd we own.
    unsafe {
        if libc::fchmod(f.as_raw_fd(), mode) != 0
            || libc::fchown(f.as_raw_fd(), uid, group.unwrap_or(u32::MAX)) != 0
        {
            return Err(err!(
                "cannot hand {} to uid {uid}: {}",
                dir.display(),
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

/// Runs the daemon until killed.
#[allow(unused_mut)]
pub fn serve(mut cfg: Config, opts: Options) -> Result<()> {
    let mut preloaded_key = None;
    let attr;
    if util::geteuid() == 0 {
        #[cfg(target_os = "linux")]
        {
            let Some(user) = cfg.user.clone() else {
                return Err(err!(
                    "refusing to run as root. Set `user = \"bouncer\"` in the config to start as root \
                     and drop to that user (see contrib/bouncer.service), or run as an ordinary user"
                ));
            };
            let (uid, gid) = crate::config::lookup_user(&user)?;
            if uid == 0 {
                return Err(err!("`user` must not be root"));
            }
            let group = cfg
                .socket_group
                .as_deref()
                .map(crate::config::lookup_group)
                .transpose()?;
            // Fork the inspector first, while the process is single-threaded and holds nothing.
            let inspector = crate::privsep::spawn_inspector(
                uid,
                gid,
                Attributor::new(cfg.context_vars.clone(), cfg.max_chain_depth),
            )?;
            attr = AttrSource::Inspector(inspector);
            util::set_service_uid(uid);
            if cfg.mlock {
                crate::harden::raise_memlock();
            }
            for s in cfg.secret_refs() {
                s.preload()?;
            }
            if let crate::config::KeySource::Credential(_) = cfg.key {
                preloaded_key = Some(vault::load_key(&cfg.key)?);
            }
            prepare_socket_dir(&cfg.socket, uid, group)?;
            if let Some(a) = &cfg.admin_socket
                && a.parent() != cfg.socket.parent()
            {
                prepare_socket_dir(a, uid, None)?;
            }
            crate::privsep::drop_privileges(uid, gid, group)?;
            cfg.rebase_uid_defaults(uid);
            eprintln!(
                "bouncer: dropped privileges to {user} (uid {uid}); attribution runs in a separate helper"
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            return Err(err!(
                "refusing to run as root; run bouncer as an ordinary user"
            ));
        }
    } else {
        attr = AttrSource::Local(Attributor::new(
            cfg.context_vars.clone(),
            cfg.max_chain_depth,
        ));
    }

    crate::harden::disable_core_dumps();
    if cfg.deny_debugger {
        crate::harden::deny_debugger();
    }
    if cfg.mlock
        && let Some(w) = crate::harden::lock_memory()
    {
        eprintln!("bouncer: warning: {w}");
    }

    let group = cfg
        .socket_group
        .as_deref()
        .map(crate::config::lookup_group)
        .transpose()?;
    let (socket, admin_socket) = (cfg.socket.clone(), cfg.admin_socket.clone());
    let server = Server::open(cfg, opts, attr, preloaded_key)?;
    let listener = bind(&socket, server.cfg.socket_mode, group)?;
    let admin_listener = match &admin_socket {
        Some(p) => Some(bind(p, 0o600, None)?),
        None => None,
    };
    {
        let srv = server.clone();
        std::thread::Builder::new()
            .name("housekeeping".into())
            .stack_size(WORKER_STACK)
            .spawn(move || {
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                    srv.flush_rejects();
                    srv.flush_notes();
                }
            })
            .map_err(|e| err!("cannot start housekeeping thread: {e}"))?;
    }
    if let Some(l) = admin_listener {
        let srv = server.clone();
        std::thread::Builder::new()
            .name("admin-accept".into())
            .stack_size(WORKER_STACK)
            .spawn(move || accept_loop(&srv, &l, true))
            .map_err(|e| err!("cannot start admin socket thread: {e}"))?;
    }
    eprintln!(
        "bouncer: serving {} secret(s) on {}",
        server
            .vault
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .secrets
            .len(),
        socket.display()
    );
    accept_loop(&server, &listener, false);
    Ok(())
}

impl Server {
    /// Opens the store (lock, key, vault, verified audit log), reconciles the vault with the
    /// log, records `start`, and starts the sinks. Does not bind sockets.
    fn open(
        cfg: Config,
        opts: Options,
        attr: AttrSource,
        preloaded_key: Option<Key>,
    ) -> Result<Arc<Server>> {
        let lock = lock_store(&cfg)?;
        let key = match preloaded_key {
            Some(k) => k,
            None => vault::load_key(&cfg.key)?,
        };
        let (vdir, vname) = util::split_path(&cfg.vault)?;
        let vault_dir = Dir::secure(&vdir, true)?;
        let vault_name = vname.to_os_string();
        let (vault, file_hash) = Vault::load(&vault_dir, &vault_name, &key)?;
        let (mut log, verified) = AuditLog::open(
            &cfg.audit_log,
            vault::chain_key(&key),
            cfg.audit_fsync == FsyncMode::Strict,
        )?;
        let host = util::hostname();
        let found = VaultState {
            generation: vault.generation,
            hash: file_hash,
        };
        check_vault_state(
            &mut log,
            &verified,
            &found,
            &host,
            opts.accept_vault_mismatch,
        )?;
        let mut start = Entry::new("start", &host);
        start.vault_gen = Some(found.generation);
        start.note = Some(format!(
            "bouncer {} pid {} uid {}",
            env!("CARGO_PKG_VERSION"),
            std::process::id(),
            util::geteuid()
        ));
        log.append(start)?;

        let shared = log.shared.clone();
        let mut sinks = Vec::new();
        for s in &cfg.sinks {
            let (sc, h, vars) = (s.clone(), host.clone(), cfg.context_vars.clone());
            let factory = Box::new(move || sink::build(&sc, &h, &vars));
            factory().map_err(|e| err!("sink {}: {e}", s.name))?; // fail fast on bad config
            sinks.push(sink::spawn(
                s.name.clone(),
                s.kind.type_name(),
                factory,
                cfg.audit_log.clone(),
                cfg.sink_cursor(&s.name),
                shared.clone(),
            )?);
        }
        let admission = build_admission(&cfg)?;
        Ok(Arc::new(Server {
            base: policy::default_policy(cfg.min_reason_len),
            admission,
            attr,
            host,
            key,
            vault: RwLock::new(vault),
            vault_dir,
            vault_name,
            audit: Mutex::new(log),
            shared,
            write_lock: Mutex::new(()),
            rejects: Mutex::new(Rejects::default()),
            rejected_total: AtomicU64::new(0),
            sinks,
            started: util::rfc3339_ms(util::now_ms()),
            inflight: AtomicUsize::new(0),
            pool: Pool::new(cfg.max_connections),
            #[cfg(test)]
            fail_dir_sync: std::sync::atomic::AtomicBool::new(false),
            _lock: lock,
            cfg,
        }))
    }
}

#[cfg(feature = "net")]
fn build_admission(cfg: &Config) -> Result<Option<Box<dyn Policy>>> {
    cfg.admission
        .clone()
        .map(|a| crate::admission::Admission::new(a).map(|x| Box::new(x) as Box<dyn Policy>))
        .transpose()
}

#[cfg(not(feature = "net"))]
fn build_admission(cfg: &Config) -> Result<Option<Box<dyn Policy>>> {
    if cfg.admission.is_some() {
        return Err(err!(
            "[admission] needs the `net` feature; this build has no HTTP client"
        ));
    }
    Ok(None)
}

/// Compares the vault file with the last state the audit log committed to.
fn check_vault_state(
    log: &mut AuditLog,
    v: &audit::Verified,
    found: &VaultState,
    host: &str,
    accept: bool,
) -> Result<()> {
    let st = &v.state;
    // A change whose save was interrupted after the rename: the file on disk decides.
    if let Some(u) = &st.uncertain {
        let kept = &u.after == found;
        if kept || u.before.as_ref() == Some(found) {
            let mut e = Entry::new(if kept { "reconcile" } else { "abort" }, host);
            e.txn = Some(u.txn.clone());
            e.note = Some(if kept {
                "start-up: the vault file has this change, so it was committed".into()
            } else {
                "start-up: the vault file is from before this change, so it was not committed"
                    .into()
            });
            eprintln!(
                "bouncer: change {} (saved without a confirmed directory fsync) was {}",
                u.txn,
                if kept {
                    "kept"
                } else {
                    "lost; recorded as aborted"
                }
            );
            log.append(e)?;
            return Ok(());
        }
    }
    if st.current.as_ref() == Some(found) {
        return Ok(());
    }
    let expected = match &st.current {
        Some(s) => format!(
            "generation {} (sha256 {})",
            s.generation,
            &s.hash[..16.min(s.hash.len())]
        ),
        None => "no vault state (the log is empty or has no init entry)".into(),
    };
    let msg = format!(
        "the vault file (generation {}, sha256 {}) does not match the audit log, which expects {expected}. \
         The vault may have been rolled back or replaced, or the log truncated",
        found.generation,
        &found.hash[..16]
    );
    // A crash between logging a change and saving the vault looks the same as rolling the
    // vault back by one change, so it is not recovered automatically.
    let crash_hint = match &st.last_txn {
        Some((txn, before, seq)) if *seq == v.head.seq && before.as_ref() == Some(found) => {
            format!(
                ". The vault matches the state before the last logged change (txn {txn}); that is what a crash while saving it looks like"
            )
        }
        _ => String::new(),
    };
    let msg = format!("{msg}{crash_hint}");
    if !accept {
        return Err(err!(
            "{msg}. Refusing to serve. If you know why (for example you restored a backup), start once with \
             `bouncer serve --accept-vault-mismatch`; that is recorded in the audit log"
        ));
    }
    eprintln!("bouncer: warning: {msg}; continuing because of --accept-vault-mismatch");
    let mut e = Entry::new("accept_vault_mismatch", host);
    e.vault_gen = Some(found.generation);
    e.vault_hash = Some(found.hash.clone());
    e.note = Some(format!("expected {expected}"));
    log.append(e)?;
    Ok(())
}

fn accept_loop(srv: &Arc<Server>, listener: &UnixListener, admin: bool) {
    let mut backoff = Duration::from_millis(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                backoff = Duration::from_millis(10);
                srv.dispatch(stream, admin);
            }
            Err(e) => {
                // Out of descriptors or memory: wait instead of spinning.
                let scarce = matches!(
                    e.raw_os_error(),
                    Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
                );
                if scarce {
                    eprintln!("bouncer: accept failed ({e}); backing off {backoff:?}");
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(Duration::from_secs(1));
                } else {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
}

/// Writes a short answer without reading anything, then closes.
fn answer_and_close(stream: &UnixStream, resp: Response) {
    let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
    let _ = (&*stream).write_all(&resp.encode());
    let _ = stream.shutdown(Shutdown::Both);
}

/// A pool of worker threads that grows on demand up to `max`.
///
/// A job goes to an existing worker only if one has announced it is idle and no other job has
/// claimed that announcement yet (taken atomically by the submitter). Otherwise a new worker is
/// started with the job, up to `max`. Only when all `max` workers are busy does a job wait in
/// the queue, so a slow client never holds up a fast one while there is room for a worker.
pub(crate) struct Pool<J> {
    inner: Arc<PoolInner<J>>,
    tx: Mutex<mpsc::Sender<J>>,
    total: AtomicUsize,
    max: usize,
}

struct PoolInner<J> {
    rx: Mutex<mpsc::Receiver<J>>,
    /// Workers waiting for a job that no submitter has claimed.
    idle: AtomicUsize,
    /// Jobs queued while every worker was busy, not yet claimed by a worker.
    queued: AtomicUsize,
}

impl<J: Send + 'static> Pool<J> {
    pub(crate) fn new(max: usize) -> Pool<J> {
        let (tx, rx) = mpsc::channel();
        Pool {
            inner: Arc::new(PoolInner {
                rx: Mutex::new(rx),
                idle: AtomicUsize::new(0),
                queued: AtomicUsize::new(0),
            }),
            tx: Mutex::new(tx),
            total: AtomicUsize::new(0),
            max,
        }
    }

    /// Runs `job` on a worker. `handler` is only called when a new worker is started, to
    /// make the function that worker runs jobs with. Gives the job back if no worker exists
    /// and none can be started.
    pub(crate) fn submit<F>(
        &self,
        job: J,
        handler: impl FnOnce() -> F,
    ) -> std::result::Result<(), J>
    where
        F: Fn(J) + Send + 'static,
    {
        let inner = &self.inner;
        if add_bounded(&inner.idle, -1, usize::MAX) {
            return self.send(job);
        }
        let job = if add_bounded(&self.total, 1, self.max) {
            let slot = Arc::new(Mutex::new(Some(job)));
            let (inner2, slot2, run) = (inner.clone(), slot.clone(), handler());
            let spawned = std::thread::Builder::new()
                .name("worker".into())
                .stack_size(WORKER_STACK)
                .spawn(move || {
                    let first = slot2.lock().unwrap_or_else(|e| e.into_inner()).take();
                    if let Some(j) = first {
                        run(j);
                    }
                    loop {
                        // Take a queued job's claim if there is one, else announce.
                        if !add_bounded(&inner2.queued, -1, usize::MAX) {
                            inner2.idle.fetch_add(1, Ordering::AcqRel);
                        }
                        let job = inner2.rx.lock().unwrap_or_else(|e| e.into_inner()).recv();
                        let Ok(job) = job else { return };
                        run(job);
                    }
                });
            match spawned {
                Ok(_) => return Ok(()),
                Err(e) => {
                    eprintln!("bouncer: cannot start a worker thread: {e}");
                    let total = self.total.fetch_sub(1, Ordering::AcqRel) - 1;
                    let job = slot
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .take()
                        .expect("the thread never started");
                    if total == 0 {
                        return Err(job);
                    }
                    job
                }
            }
        } else {
            job
        };
        inner.queued.fetch_add(1, Ordering::AcqRel);
        self.send(job)
    }

    fn send(&self, job: J) -> std::result::Result<(), J> {
        let tx = self.tx.lock().unwrap_or_else(|e| e.into_inner());
        tx.send(job).map_err(|e| e.0)
    }
}

/// Adds `delta` (+1 or -1) to `a` unless that would take it below 0 or above `max`.
fn add_bounded(a: &AtomicUsize, delta: isize, max: usize) -> bool {
    let mut n = a.load(Ordering::Acquire);
    loop {
        let Some(next) = n.checked_add_signed(delta).filter(|&x| x <= max) else {
            return false;
        };
        match a.compare_exchange_weak(n, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(now) => n = now,
        }
    }
}

impl Server {
    fn dispatch(self: &Arc<Self>, stream: UnixStream, admin: bool) {
        let caller = match Caller::identify(&stream) {
            Ok(c) => c,
            Err(_) => return,
        };
        let uid = caller.cred.uid;
        let ok = if admin {
            self.cfg.admin_uids.contains(&uid)
        } else {
            self.cfg.may_connect(uid)
        };
        if !ok {
            self.reject(uid);
            answer_and_close(
                &stream,
                Response::fail(E_DENIED, format!("uid {uid} may not use this daemon")),
            );
            return;
        }
        if self.inflight.fetch_add(1, Ordering::AcqRel) >= self.cfg.max_connections {
            self.inflight.fetch_sub(1, Ordering::AcqRel);
            answer_and_close(
                &stream,
                Response::fail(E_BUSY, "too many concurrent connections; try again"),
            );
            return;
        }
        let job = Job {
            stream,
            caller,
            admin_socket: admin,
        };
        if let Err(job) = self.submit(job) {
            self.inflight.fetch_sub(1, Ordering::AcqRel);
            answer_and_close(
                &job.stream,
                Response::fail(E_BUSY, "cannot start a worker; try again"),
            );
        }
    }

    fn submit(self: &Arc<Self>, job: Job) -> std::result::Result<(), Job> {
        self.pool.submit(job, || {
            let srv = self.clone();
            move |job: Job| {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| srv.handle(&job)));
                srv.inflight.fetch_sub(1, Ordering::AcqRel);
            }
        })
    }

    fn reject(&self, uid: u32) {
        self.rejected_total.fetch_add(1, Ordering::Relaxed);
        let mut r = self.rejects.lock().unwrap_or_else(|e| e.into_inner());
        r.count += 1;
        if r.uids.len() < 16 {
            r.uids.insert(uid);
        }
        drop(r);
        self.flush_rejects();
    }

    /// Writes at most one `reject` entry per interval, summarising rejected connections.
    fn flush_rejects(&self) {
        let mut r = self.rejects.lock().unwrap_or_else(|e| e.into_inner());
        let due = r
            .last_logged
            .is_none_or(|t| t.elapsed() >= REJECT_LOG_INTERVAL);
        if r.count == 0 || !due {
            return;
        }
        let mut e = Entry::new("reject", &self.host);
        e.count = std::mem::take(&mut r.count);
        e.uids = std::mem::take(&mut r.uids).into_iter().collect();
        e.note = Some("connections from uids not allowed to connect; closed before reading".into());
        r.last_logged = Some(Instant::now());
        drop(r);
        let _ = self
            .audit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .append(e);
    }

    /// Records notes from the sink threads (quarantined entries) in the audit log.
    fn flush_notes(&self) {
        for n in self.shared.take_notes() {
            let mut e = Entry::new("sink_reject", &self.host);
            e.note = Some(n);
            let _ = self.append(e);
        }
    }

    fn attribute(&self, caller: &Caller) -> Attribution {
        let pid = caller.cred.pid;
        if pid <= 0 {
            return Attribution::unavailable(
                "the kernel did not report the caller's pid (another pid namespace?)",
            );
        }
        let at = match &self.attr {
            AttrSource::Local(a) => a.attribute(pid),
            #[cfg(target_os = "linux")]
            AttrSource::Inspector(i) => i.attribute(pid),
        };
        if !caller.still_same() {
            return Attribution::unavailable(
                "the caller exited or was replaced during attribution",
            );
        }
        at
    }

    fn handle(&self, job: &Job) {
        let deadline = Instant::now() + self.cfg.request_timeout;
        let at = self.attribute(&job.caller);
        let resp = match proto::read_frame(
            &job.stream,
            deadline,
            proto::MAX_FRAME,
            proto::MAX_SET_FRAME,
        ) {
            Err(e) => Response::fail(E_BAD_REQUEST, e.to_string()),
            // Never echo the parse error: a malformed `set` could contain the value.
            Ok(buf) => match serde_json::from_slice::<Request>(&buf) {
                Err(_) => Response::fail(E_BAD_REQUEST, "malformed request"),
                Ok(req) => self.process(req, job, &at),
            },
        };
        let left = deadline.saturating_duration_since(Instant::now());
        let _ = job
            .stream
            .set_write_timeout(Some(left.max(Duration::from_secs(1))));
        let _ = (&job.stream).write_all(&resp.encode());
        let _ = job.stream.shutdown(Shutdown::Write);
        // Let the client read the answer before the socket closes.
        let _ = job
            .stream
            .set_read_timeout(Some(Duration::from_millis(100)));
        let _ = (&job.stream).read(&mut [0u8; 1]);
    }

    fn process(&self, req: Request, job: &Job, at: &Attribution) -> Response {
        if let Some(msg) = validate(&req) {
            return Response::fail(E_BAD_REQUEST, msg);
        }
        let peer = job.caller.cred;
        match req.op {
            Op::Status => self.status(),
            Op::Verify => self.verify(&req, peer),
            Op::Ls => self.list(&req, peer, at),
            Op::Get | Op::Exec => self.read(&req, peer, at),
            Op::Set | Op::Rm => self.write(&req, peer, at, job.admin_socket),
        }
    }

    fn audit_failed(&self) -> Option<Response> {
        self.shared.failed().map(|why| {
            Response::fail(
                E_AUDIT,
                format!("the audit log failed ({why}); nothing is released until `bouncer repair` and a restart"),
            )
        })
    }

    fn entry(&self, req: &Request, peer: PeerCred, at: &Attribution) -> Entry {
        let mut e = Entry::new(req.op.as_str(), &self.host);
        e.names = req.names.clone();
        e.reason = req.reason.trim().to_string();
        e.peer = Some(peer);
        e.attribution = Some(at.clone());
        e
    }

    fn append(&self, e: Entry) -> Result<audit::Head> {
        self.audit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .append(e)
    }

    fn list(&self, req: &Request, peer: PeerCred, at: &Attribution) -> Response {
        if let Some(r) = self.audit_failed() {
            return r;
        }
        // One page: names after `after`, at most LS_PAGE of them and, encoded, well inside
        // MAX_RESPONSE. `next` says where the following page starts.
        let mut resp = Response {
            ok: true,
            ..Default::default()
        };
        {
            use std::ops::Bound;
            let v = self.vault.read().unwrap_or_else(|e| e.into_inner());
            let from = match &req.after {
                Some(a) => Bound::Excluded(a.as_str()),
                None => Bound::Unbounded,
            };
            let mut size = 0;
            for (name, s) in v.secrets.range::<str, _>((from, Bound::Unbounded)) {
                let item = ListItem {
                    name: name.clone(),
                    desc: s.desc.clone(),
                    tags: s.tags.clone(),
                    updated: s.updated.clone(),
                };
                size += encoded_len(&item) + 1;
                if resp.list.len() == proto::LS_PAGE || size > proto::MAX_RESPONSE - 4096 {
                    resp.next = resp.list.last().map(|i| i.name.clone());
                    break;
                }
                resp.list.push(item);
            }
        }
        let mut e = self.entry(req, peer, at);
        e.decision = "allow";
        e.result = "ok";
        if let Err(err) = self.append(e) {
            return Response::fail(E_AUDIT, format!("audit log write failed: {err}"));
        }
        resp
    }

    fn read(&self, req: &Request, peer: PeerCred, at: &Attribution) -> Response {
        if let Some(r) = self.audit_failed() {
            return r;
        }
        let reason = req.reason.trim();
        let thread = at.thread(&self.cfg.context_vars).map(str::to_string);
        let mut e = self.entry(req, peer, at);
        // The decision is bound to the versions it was made on. If a secret changes while the
        // policies (or the model) run, decide again on the new version, once; a second change
        // is denied.
        let mut changed_twice = false;
        let (verdict, outcome) = loop {
            // Metadata only; the lock is not held while policies (or the model) run.
            let (metas, missing): (Vec<Meta>, Vec<String>) = {
                let v = self.vault.read().unwrap_or_else(|e| e.into_inner());
                let mut metas = Vec::new();
                let mut missing = Vec::new();
                for n in &req.names {
                    match v.secrets.get(n) {
                        Some(s) => metas.push(Meta {
                            name: n.clone(),
                            desc: s.desc.clone(),
                            tags: s.tags.clone(),
                            rev: s.rev,
                        }),
                        None => missing.push(n.clone()),
                    }
                }
                (metas, missing)
            };
            let input = PolicyInput {
                op: req.op,
                secrets: metas
                    .iter()
                    .map(|m| SecretMeta {
                        name: &m.name,
                        desc: m.desc.as_deref(),
                        tags: &m.tags,
                        rev: m.rev,
                    })
                    .collect(),
                caller: policy::Caller {
                    peer,
                    attribution: at,
                    thread: thread.as_deref(),
                },
                reason,
            };
            let verdict = self.decide(&input, at, &metas, missing.is_empty());
            if verdict.decision != Decision::Allow {
                break (verdict, Outcome::Denied);
            }
            if !missing.is_empty() {
                break (verdict, Outcome::Missing(missing));
            }
            let v = self.vault.read().unwrap_or_else(|e| e.into_inner());
            let values: Option<Vec<SecretValue>> = metas
                .iter()
                .map(|m| {
                    v.secrets
                        .get(&m.name)
                        .filter(|s| s.rev == m.rev)
                        .map(|s| SecretValue(s.value.clone()))
                })
                .collect();
            drop(v);
            match values {
                Some(values) => break (verdict, Outcome::Release(values)),
                None if !changed_twice => changed_twice = true,
                None => break (verdict, Outcome::Changed),
            }
        };
        e.policy = verdict.policy;
        e.admission = verdict.admission.clone();
        let mut resp = match outcome {
            Outcome::Denied => {
                let why = match &verdict.decision {
                    Decision::Deny(why) => why.clone(),
                    _ => "denied".to_string(),
                };
                e.decision = "deny";
                e.result = "denied";
                e.why = Some(why.clone());
                Response::fail(E_DENIED, why)
            }
            Outcome::Missing(missing) => {
                e.decision = "allow";
                e.result = "not_found";
                Response::fail(
                    E_NOT_FOUND,
                    format!("no secret named {}", missing.join(", ")),
                )
            }
            Outcome::Changed => {
                let why = "a requested secret changed twice while the request was being decided; try again";
                e.decision = "deny";
                e.result = "denied";
                e.why = Some(why.into());
                Response::fail(E_DENIED, why)
            }
            Outcome::Release(values) => {
                e.decision = "allow";
                e.result = "ok";
                Response {
                    ok: true,
                    values,
                    ..Default::default()
                }
            }
        };
        resp.reasoning = verdict.reasoning;
        if resp.ok && encoded_len(&resp) > proto::MAX_RESPONSE {
            resp = Response::fail(
                E_BAD_REQUEST,
                "the requested values are too large for one response; ask for fewer",
            );
            e.result = "error";
            e.why = Some("response too large".into());
        }
        if let Err(err) = self.append(e) {
            return Response::fail(
                E_AUDIT,
                format!("audit log write failed, refusing to release secrets: {err}"),
            );
        }
        resp
    }

    fn decide(
        &self,
        input: &PolicyInput,
        at: &Attribution,
        metas: &[Meta],
        all_found: bool,
    ) -> Verdict {
        let deny = |policy, why: String| Verdict {
            decision: Decision::Deny(why),
            policy,
            reasoning: None,
            admission: None,
        };
        if at.is_unavailable() && self.cfg.require_attribution {
            return deny(
                "require-attribution",
                format!(
                    "the caller could not be attributed ({}); denied because require_attribution = true",
                    at.error.as_deref().unwrap_or("unknown reason")
                ),
            );
        }
        let base = self.base.verdict(input);
        if base.decision != Decision::Allow || !all_found {
            return base;
        }
        let tags: Vec<&[String]> = metas.iter().map(|m| m.tags.as_slice()).collect();
        #[cfg(feature = "net")]
        let required = crate::admission::required(&tags, self.admission.is_some());
        #[cfg(not(feature = "net"))]
        let required = tags
            .iter()
            .any(|t| t.iter().any(|x| x == "admission/always"));
        if !required {
            return base;
        }
        match &self.admission {
            Some(a) => a.verdict(input),
            None => deny(
                "admission",
                "a requested secret is tagged admission/always, but [admission] is not enabled"
                    .into(),
            ),
        }
    }

    fn write(
        &self,
        req: &Request,
        peer: PeerCred,
        at: &Attribution,
        admin_socket: bool,
    ) -> Response {
        if let Some(r) = self.audit_failed() {
            return r;
        }
        let mut e = self.entry(req, peer, at);
        e.policy = "admin";
        let refuse = |mut e: Entry, why: String| -> Response {
            e.decision = "deny";
            e.result = "denied";
            e.why = Some(why.clone());
            match self.append(e) {
                Ok(_) => Response::fail(E_DENIED, why),
                Err(err) => Response::fail(E_AUDIT, format!("audit log write failed: {err}")),
            }
        };
        if !self.cfg.admin_uids.contains(&peer.uid) {
            return refuse(
                e,
                format!(
                    "uid {} may not change secrets (not in admin_uids)",
                    peer.uid
                ),
            );
        }
        if self.cfg.admin_socket.is_some() && !admin_socket {
            return refuse(e, "changes are only accepted on the admin socket".into());
        }
        if self.cfg.require_write_reason && req.reason.trim().is_empty() {
            return refuse(
                e,
                "a reason is required for set and rm (require_write_reason = true)".into(),
            );
        }
        let _serial = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let name = &req.names[0];
        let mut next = self.vault.read().unwrap_or_else(|e| e.into_inner()).clone();
        let now = util::rfc3339_ms(util::now_ms());
        if req.op == Op::Rm {
            if next.secrets.remove(name).is_none() {
                e.decision = "allow";
                e.result = "not_found";
                return match self.append(e) {
                    Ok(_) => Response::fail(E_NOT_FOUND, format!("no secret named {name}")),
                    Err(err) => Response::fail(E_AUDIT, format!("audit log write failed: {err}")),
                };
            }
        } else {
            let old = next.secrets.get(name);
            let created = old
                .map(|s| s.created.clone())
                .unwrap_or_else(|| now.clone());
            let desc = req
                .desc
                .clone()
                .or_else(|| old.and_then(|s| s.desc.clone()));
            let tags = if req.tags.is_empty() {
                old.map(|s| s.tags.clone()).unwrap_or_default()
            } else {
                req.tags.clone()
            };
            let value = req.value.as_ref().map(|v| v.0.clone()).unwrap_or_default();
            next.secrets.insert(
                name.clone(),
                Secret {
                    value,
                    desc,
                    tags,
                    created,
                    updated: now,
                    rev: next.generation + 1,
                },
            );
        }
        next.generation += 1;
        let bytes = match next.encrypt(&self.key) {
            Ok(b) => b,
            Err(err) => return Response::fail(E_INTERNAL, err.0),
        };
        let txn = util::random_hex::<8>().unwrap_or_else(|_| format!("{:x}", util::now_ms()));
        e.decision = "allow";
        e.result = "ok";
        e.txn = Some(txn.clone());
        e.vault_gen = Some(next.generation);
        e.vault_hash = Some(util::sha256_hex(&bytes));
        // 1. Audit first.
        if let Err(err) = self.append(e) {
            return Response::fail(
                E_AUDIT,
                format!("audit log write failed; nothing changed: {err}"),
            );
        }
        // 2. Persist. Cached admission decisions are dropped whatever the outcome.
        let saved = self.save_vault(&bytes);
        if let Some(a) = &self.admission {
            a.invalidate();
        }
        match saved {
            Ok(()) => {}
            Err(WriteError::NotReplaced(err)) => {
                let mut abort = Entry::new("abort", &self.host);
                abort.txn = Some(txn);
                abort.why = Some(err.0.clone());
                let logged = self.append(abort);
                return Response::fail(
                    E_INTERNAL,
                    format!(
                        "could not save the vault ({err}); the change was rolled back{}",
                        if logged.is_err() {
                            " (and the audit log failed too)"
                        } else {
                            ""
                        }
                    ),
                );
            }
            Err(WriteError::Uncertain(err)) => {
                // The new vault is on disk but may not survive a crash, so this is neither a
                // commit nor an abort. Record that, and stop serving until a restart lets the
                // file on disk decide (see check_vault_state).
                let mut e = Entry::new("commit_uncertain", &self.host);
                e.txn = Some(txn.clone());
                e.why = Some(err.0.clone());
                let logged = self.append(e);
                let _ = self.shared.latch(format!(
                    "the vault save for change {txn} may not be durable ({err})"
                ));
                return Response::fail(
                    E_INTERNAL,
                    format!(
                        "the vault file was replaced, but the change may not survive a crash ({err}){}. \
                         The daemon now refuses requests: fix the cause, run `bouncer repair` and restart; \
                         start-up then checks the vault file and records whether the change was kept",
                        if logged.is_err() {
                            " (and the audit log failed too)"
                        } else {
                            ""
                        }
                    ),
                );
            }
        }
        // 3. Publish.
        *self.vault.write().unwrap_or_else(|e| e.into_inner()) = next;
        Response {
            ok: true,
            ..Default::default()
        }
    }

    fn save_vault(&self, bytes: &[u8]) -> std::result::Result<(), WriteError> {
        #[cfg(test)]
        if self.fail_dir_sync.load(Ordering::Acquire) {
            return self
                .vault_dir
                .replace_failing_dir_sync(&self.vault_name, bytes, 0o600);
        }
        self.vault_dir.replace(&self.vault_name, bytes, 0o600)
    }

    fn status(&self) -> Response {
        let head = self.shared.head();
        let sinks: Vec<serde_json::Value> = self
            .sinks
            .iter()
            .map(|s| {
                let s = s.lock().unwrap_or_else(|e| e.into_inner()).clone();
                let mut v = serde_json::to_value(&s).unwrap_or_default();
                v["lag"] = head.seq.saturating_sub(s.delivered_seq).into();
                v
            })
            .collect();
        let (gen_, count) = {
            let v = self.vault.read().unwrap_or_else(|e| e.into_inner());
            (v.generation, v.secrets.len())
        };
        let status = serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "pid": std::process::id(),
            "uid": util::geteuid(),
            "started": self.started,
            "socket": self.cfg.socket,
            "secrets": count,
            "vault_generation": gen_,
            "audit": {
                "path": self.cfg.audit_log,
                "head": format!("{}:{}", head.seq, head.mac),
                "seq": head.seq,
                "mac": head.mac,
                "log_id": head.log_id,
                "failed": self.shared.failed(),
                "fsync": if self.cfg.audit_fsync == FsyncMode::Strict { "strict" } else { "async" },
            },
            "sinks": sinks,
            "admission": self.cfg.admission.as_ref().map(|a| serde_json::json!({
                "provider": format!("{:?}", a.provider).to_lowercase(),
                "model": a.model,
                "on_error": if a.on_error_allow { "allow" } else { "deny" },
            })),
            "rejected_connections": self.rejected_total.load(Ordering::Relaxed),
            "inflight": self.inflight.load(Ordering::Relaxed),
        });
        Response {
            ok: true,
            status: Some(status),
            ..Default::default()
        }
    }

    fn verify(&self, req: &Request, peer: PeerCred) -> Response {
        if !self.cfg.admin_uids.contains(&peer.uid) {
            return Response::fail(
                E_DENIED,
                "only admin_uids may run verify through the daemon",
            );
        }
        let expect = match req
            .expect_head
            .as_deref()
            .map(audit::parse_head)
            .transpose()
        {
            Ok(e) => e,
            Err(e) => return Response::fail(E_BAD_REQUEST, e.0),
        };
        let len = self.audit.lock().unwrap_or_else(|e| e.into_inner()).len();
        let r = util::open_nofollow(&self.cfg.audit_log)
            .map_err(util::Error::from)
            .and_then(|f| {
                audit::verify_reader(
                    f.take(len),
                    Some(&vault::chain_key(&self.key)),
                    expect.as_ref().map(|(s, h)| (*s, h.as_str())),
                )
            });
        match r {
            Ok(v) => Response {
                ok: true,
                status: Some(serde_json::json!({
                    "entries": v.entries,
                    "head": format!("{}:{}", v.head.seq, v.head.mac),
                    "log_id": v.head.log_id,
                })),
                ..Default::default()
            },
            Err(e) => Response::fail(E_VERIFY, e.0),
        }
    }
}

fn validate(req: &Request) -> Option<String> {
    let needs_names = req.op.is_read() || req.op.is_write();
    if needs_names && req.names.is_empty() {
        return Some("no secret name given".into());
    }
    if req.op.is_write() && req.names.len() != 1 {
        return Some("set and rm take exactly one name".into());
    }
    if req.names.len() > MAX_NAMES {
        return Some(format!("at most {MAX_NAMES} names per request"));
    }
    if let Some(a) = &req.after
        && (req.op != Op::Ls || !valid_name(a))
    {
        return Some("`after` takes a secret name, for ls only".into());
    }
    if let Some(n) = req.names.iter().find(|n| !valid_name(n)) {
        let shown = util::escape(&util::cap(n, 64)).into_owned();
        return Some(format!(
            "invalid secret name `{shown}` (use A-Z a-z 0-9 _ . - /, max 128)"
        ));
    }
    if req.reason.chars().count() > MAX_REASON {
        return Some(format!("reason is longer than {MAX_REASON} characters"));
    }
    if req.op == Op::Set {
        let v = req.value.as_ref().map(|v| v.0.as_str()).unwrap_or("");
        if v.is_empty() {
            return Some("set needs a non-empty value".into());
        }
        if v.len() > proto::MAX_VALUE {
            return Some(format!("values are limited to {} bytes", proto::MAX_VALUE));
        }
        if req.desc.as_deref().unwrap_or("").chars().count() > MAX_DESC {
            return Some(format!("description is longer than {MAX_DESC} characters"));
        }
        if req.tags.len() > MAX_TAGS {
            return Some(format!("at most {MAX_TAGS} tags"));
        }
        if let Some(t) = req.tags.iter().find(|t| !valid_name(t)) {
            let shown = util::escape(&util::cap(t, 64)).into_owned();
            return Some(format!("invalid tag `{shown}`"));
        }
    }
    None
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A daemon on a fresh store in a temp directory, without sockets or sinks.
    pub(crate) struct TestServer {
        srv: Option<Arc<Server>>,
        pub dir: std::path::PathBuf,
        pub cfg: Config,
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    static N: AtomicUsize = AtomicUsize::new(0);

    pub(crate) fn config(dir: &Path, extra: &str) -> Config {
        let mut cfg = Config::load(Some(dir.join("absent.toml")), None).unwrap();
        cfg.apply(crate::config::parse_toml(extra).unwrap())
            .unwrap();
        cfg.vault = dir.join("vault.bin");
        cfg.audit_log = dir.join("audit.jsonl");
        cfg.key = crate::config::KeySource::File(dir.join("key"));
        cfg.socket = dir.join("bouncer.sock");
        cfg.mlock = false;
        cfg
    }

    /// Creates the key, an empty vault and the log, like `bouncer init`.
    pub(crate) fn init_store(cfg: &Config) {
        let crate::config::KeySource::File(k) = &cfg.key else {
            unreachable!()
        };
        vault::generate_key_file(k).unwrap();
        let key = vault::load_key(&cfg.key).unwrap();
        let v = Vault {
            generation: 1,
            ..Default::default()
        };
        let bytes = v.encrypt(&key).unwrap();
        let (mut log, _) = AuditLog::open(&cfg.audit_log, vault::chain_key(&key), true).unwrap();
        let mut e = Entry::new("init", "h");
        e.vault_gen = Some(1);
        e.vault_hash = Some(util::sha256_hex(&bytes));
        log.append(e).unwrap();
        util::write_file_atomic(&cfg.vault, &bytes, 0o600).unwrap();
    }

    pub(crate) fn start(cfg: Config) -> Result<Arc<Server>> {
        let attr = AttrSource::Local(Attributor::new(
            cfg.context_vars.clone(),
            cfg.max_chain_depth,
        ));
        Server::open(cfg, Options::default(), attr, None)
    }

    impl TestServer {
        pub(crate) fn new(extra: &str) -> TestServer {
            TestServer::with(|_| extra.to_string())
        }

        /// `extra` gets the store directory, to put files there and refer to them.
        pub(crate) fn with(extra: impl FnOnce(&Path) -> String) -> TestServer {
            let dir = std::env::temp_dir().join(format!(
                "bouncer-srv-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            let extra = extra(&dir);
            let cfg = config(&dir, &extra);
            init_store(&cfg);
            TestServer {
                srv: Some(start(cfg.clone()).unwrap()),
                dir,
                cfg,
            }
        }

        pub(crate) fn srv(&self) -> &Arc<Server> {
            self.srv.as_ref().expect("the server is running")
        }

        /// Stops the daemon (releasing the store lock) and starts it again.
        pub(crate) fn restart(&mut self) -> Result<()> {
            self.srv = None;
            self.srv = Some(start(self.cfg.clone())?);
            Ok(())
        }

        pub(crate) fn call(&self, req: Request) -> Response {
            let (a, _b) = UnixStream::pair().unwrap();
            let job = Job {
                caller: Caller::identify(&a).unwrap(),
                stream: a,
                admin_socket: false,
            };
            let at = Attribution {
                status: "ok".into(),
                ..Default::default()
            };
            self.srv().process(req, &job, &at)
        }

        pub(crate) fn set(&self, name: &str, value: &str) -> Response {
            let mut req = Request::new(Op::Set, vec![name.into()], String::new());
            req.value = Some(SecretValue(value.into()));
            self.call(req)
        }

        pub(crate) fn get(&self, name: &str) -> Response {
            self.call(Request::new(
                Op::Get,
                vec![name.into()],
                "unit test of the server".into(),
            ))
        }

        pub(crate) fn ops(&self) -> Vec<serde_json::Value> {
            std::fs::read_to_string(&self.cfg.audit_log)
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        }
    }

    #[test]
    fn save_failure_before_rename_is_a_rollback() {
        let t = TestServer::new("");
        assert!(t.set("A", "old-value").ok);
        std::fs::set_permissions(&t.dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let r = t.set("A", "new-value");
        std::fs::set_permissions(&t.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Root ignores the directory mode; nothing to check then.
        if util::geteuid() == 0 {
            return;
        }
        assert!(r.error.unwrap().contains("rolled back"));
        assert_eq!(t.get("A").values[0].0, "old-value");
        let ops = t.ops();
        assert_eq!(ops[ops.len() - 2]["op"], "abort");
        assert!(
            t.srv().shared.failed().is_none(),
            "a clean rollback does not latch"
        );
    }

    #[test]
    fn save_failure_after_rename_is_uncertain_and_reconciled() {
        for kept in [true, false] {
            let mut t = TestServer::new("");
            assert!(t.set("A", "old-value").ok);
            let old_vault = std::fs::read(&t.cfg.vault).unwrap();
            t.srv().fail_dir_sync.store(true, Ordering::Release);
            let r = t.set("A", "new-value");
            let msg = r.error.unwrap();
            assert!(msg.contains("may not survive a crash"), "{msg}");
            assert!(!msg.contains("rolled back"), "{msg}");
            // Not reported as an abort, and the daemon is latched, on disk too.
            let ops = t.ops();
            let last = ops.last().unwrap();
            assert_eq!(last["op"], "commit_uncertain");
            assert_eq!(last["txn"], ops[ops.len() - 2]["txn"]);
            assert!(!ops.iter().any(|e| e["op"] == "abort"));
            assert_eq!(t.get("A").code.as_deref(), Some(E_AUDIT));
            // The new vault is on disk; a crash may or may not have kept it.
            if !kept {
                std::fs::write(&t.cfg.vault, &old_vault).unwrap();
            }
            let e = t.restart().err().unwrap().to_string();
            assert!(e.contains("bouncer repair"), "{e}");
            audit::repair(
                &t.cfg.audit_log,
                Some(&vault::chain_key(&vault::load_key(&t.cfg.key).unwrap())),
            )
            .unwrap();
            // Start-up lets the vault file decide, without --accept-vault-mismatch.
            t.restart().unwrap();
            let want = if kept { "new-value" } else { "old-value" };
            assert_eq!(t.get("A").values[0].0, want);
            let ops = t.ops();
            let txn = &ops.iter().find(|e| e["op"] == "commit_uncertain").unwrap()["txn"];
            let settle = &ops[ops.len() - 3];
            assert_eq!(settle["op"], if kept { "reconcile" } else { "abort" });
            assert_eq!(&settle["txn"], txn);
            // And it stays settled across another restart.
            t.restart().unwrap();
            assert_eq!(t.get("A").values[0].0, want);
        }
    }

    /// A model that waits for the test before answering the first `pause` calls, so the test
    /// can change a secret while a decision is being made. Returns the server and the number
    /// of model calls.
    #[cfg(feature = "net")]
    fn paused_admission(
        pause: usize,
    ) -> (
        TestServer,
        Arc<AtomicUsize>,
        mpsc::Receiver<()>,
        mpsc::Sender<()>,
    ) {
        let (in_model_tx, in_model) = mpsc::channel::<()>();
        let (go, go_rx) = mpsc::channel::<()>();
        let (in_model_tx, go_rx) = (Mutex::new(in_model_tx), Mutex::new(go_rx));
        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        let (port, _) = crate::sink::testutil::serve(Arc::new(move |_| {
            if c.fetch_add(1, Ordering::SeqCst) < pause {
                in_model_tx.lock().unwrap().send(()).unwrap();
                go_rx.lock().unwrap().recv().unwrap();
            }
            let text = r#"{"decision":"allow","reasoning":"fine"}"#;
            let body = serde_json::json!({"content": [{"type": "text", "text": text}]});
            (200, body.to_string())
        }));
        let t = TestServer::with(|dir| {
            let key = dir.join("llm-key");
            util::write_file_atomic(&key, b"fake-llm-key", 0o600).unwrap();
            format!(
                "[admission]\nenabled = true\nendpoint = \"http://127.0.0.1:{port}/v1/messages\"\n\
                 allow_insecure_http = true\nmodel = \"m\"\napi_key_file = \"{}\"\n",
                key.display()
            )
        });
        (t, calls, in_model, go)
    }

    #[cfg(feature = "net")]
    #[test]
    fn admission_is_bound_to_the_versions_it_decided_on() {
        // Changed once while the model decides: decided again, and the new value released.
        let (t, calls, in_model, go) = paused_admission(1);
        assert!(t.set("A", "version-one").ok);
        std::thread::scope(|s| {
            let h = s.spawn(|| t.get("A"));
            in_model.recv().unwrap();
            assert!(t.set("A", "version-two").ok);
            go.send(()).unwrap();
            let r = h.join().unwrap();
            assert!(r.ok, "{:?}", r.error);
            assert_eq!(r.values[0].0, "version-two");
        });
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "decided again on the new version"
        );

        // Changed again during the second decision: denied, nothing released.
        let (t, calls, in_model, go) = paused_admission(2);
        assert!(t.set("A", "version-one").ok);
        std::thread::scope(|s| {
            let h = s.spawn(|| t.get("A"));
            for v in ["version-two", "version-three"] {
                in_model.recv().unwrap();
                assert!(t.set("A", v).ok);
                go.send(()).unwrap();
            }
            let r = h.join().unwrap();
            assert!(!r.ok && r.values.is_empty());
            assert!(r.error.unwrap().contains("changed"));
        });
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        let last = t.ops().pop().unwrap();
        assert_eq!(
            (last["op"].as_str(), last["result"].as_str()),
            (Some("get"), Some("denied"))
        );
    }

    /// A job submitted right after another one is never queued behind it while the pool has
    /// room for another worker, even when an idle worker has not picked up the first yet.
    #[test]
    fn pool_does_not_queue_behind_a_busy_worker() {
        enum J {
            Block(Arc<(Mutex<bool>, std::sync::Condvar)>),
            Quick(mpsc::Sender<()>),
        }
        let pool: Pool<J> = Pool::new(64);
        let run = || {
            |j: J| match j {
                J::Block(g) => {
                    let mut open = g.0.lock().unwrap();
                    while !*open {
                        open = g.1.wait(open).unwrap();
                    }
                }
                J::Quick(tx) => tx.send(()).unwrap(),
            }
        };
        for _ in 0..40 {
            // One or more workers that finished a job and wait for the next.
            let (tx, rx) = mpsc::channel();
            assert!(pool.submit(J::Quick(tx), run).is_ok());
            rx.recv().unwrap();
            std::thread::sleep(Duration::from_millis(1));
            let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
            let (tx, rx) = mpsc::channel();
            let (block, quick) = (J::Block(gate.clone()), J::Quick(tx));
            // As many blocking jobs as there are idle workers, then a quick one at once.
            let idle = pool.inner.idle.load(Ordering::Acquire);
            assert!(pool.submit(block, run).is_ok());
            for _ in 1..idle {
                assert!(pool.submit(J::Block(gate.clone()), run).is_ok());
            }
            assert!(pool.submit(quick, run).is_ok());
            let fast = rx.recv_timeout(Duration::from_secs(2));
            *gate.0.lock().unwrap() = true;
            gate.1.notify_all();
            assert!(fast.is_ok(), "the quick job waited behind a blocked one");
        }
        assert!(pool.total.load(Ordering::Acquire) <= 64);
    }

    fn insert(t: &TestServer, name: String, value: String, desc: Option<String>) {
        let mut v = t.srv().vault.write().unwrap();
        let rev = v.generation;
        v.secrets.insert(
            name,
            Secret {
                value,
                desc,
                tags: vec![],
                created: "t".into(),
                updated: "t".into(),
                rev,
            },
        );
    }

    #[test]
    fn ls_is_paged_within_the_response_limit() {
        let t = TestServer::new("");
        // 2500 descriptions of 500 control characters encode to about 3 KB each, 7.5 MB in all.
        for i in 0..2500 {
            insert(
                &t,
                format!("S{i:05}"),
                "v".into(),
                Some("\u{1}".repeat(500)),
            );
        }
        let (mut names, mut after, mut pages) = (Vec::new(), None, 0);
        loop {
            let mut req = Request::new(Op::Ls, vec![], String::new());
            req.after = after.take();
            let r = t.call(req);
            assert!(r.ok, "{:?}", r.error);
            assert!(encoded_len(&r) <= proto::MAX_RESPONSE);
            assert!(r.list.len() <= proto::LS_PAGE);
            names.extend(r.list.iter().map(|i| i.name.clone()));
            pages += 1;
            match r.next {
                Some(n) => after = Some(n),
                None => break,
            }
        }
        assert!(pages >= 2, "{pages}");
        assert_eq!(names.len(), 2500);
        assert!(
            names.windows(2).all(|w| w[0] < w[1]),
            "in order, no repeats"
        );
        let mut bad = Request::new(Op::Get, vec!["A".into()], "a reason here".into());
        bad.after = Some("x".into());
        assert_eq!(t.call(bad).code.as_deref(), Some(E_BAD_REQUEST));
    }

    #[test]
    fn get_limit_counts_the_encoded_response() {
        let t = TestServer::new("");
        // 3 x 256 KiB of control characters: 768 KiB of values, but over 4 MiB as JSON.
        for n in ["A", "B", "C"] {
            insert(&t, n.into(), "\u{1}".repeat(proto::MAX_VALUE), None);
        }
        let names = vec!["A".to_string(), "B".into(), "C".into()];
        let r = t.call(Request::new(Op::Exec, names, "a reason here".into()));
        assert!(!r.ok && r.values.is_empty());
        assert!(r.error.unwrap().contains("too large"));
        let last = t.ops().pop().unwrap();
        assert_eq!(last["result"], "error", "not recorded as released");
        // One of them fits.
        let r = t.call(Request::new(
            Op::Get,
            vec!["A".into()],
            "a reason here".into(),
        ));
        assert!(r.ok);
        assert_eq!(t.ops().pop().unwrap()["result"], "ok");
    }
}
