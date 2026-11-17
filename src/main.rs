use std::ffi::OsString;
use std::io::{self, BufRead, Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

use bouncer::config::{Config, KeySource};
use bouncer::proto::{self, CallError, Op, Request, Response, SecretValue};
use bouncer::redact::Redactor;
use bouncer::util::{self, Result, escape};
use bouncer::vault::{self, Vault};
use bouncer::{audit, err, server};
use zeroize::Zeroizing;

mod doctor;

const USAGE: &str = "\
bouncer: a local secret store for agents. Every read needs a reason and is audit-logged.

Usage: bouncer [--config FILE] [--socket PATH] <command>

Commands:
  init                          Create the key, an empty vault, the audit log and a config template
  keygen                        Print a new random key (for key_credential / key_command setups)
  serve [--accept-vault-mismatch]
                                Run the daemon (holds decrypted secrets in memory)
  get NAME --reason TEXT [-n]   Print a secret to stdout (-n adds a trailing newline)
  exec --reason TEXT NAME[=ENV]... -- CMD [ARGS...]
                                Run CMD with secrets in its environment; secret values in
                                its stdout/stderr are replaced with [REDACTED:<n>]
  set NAME [--desc TEXT] [--tag TAG]... [--reason TEXT] [--raw]
                                Store a secret read from stdin (one trailing newline is
                                stripped unless --raw)
  rm NAME [--reason TEXT]       Delete a secret
  ls [--json]                   List secret names and metadata (never values)
  log [--since WHEN] [--thread ID] [--name NAME] [--tail N] [--json]
                                Show the local audit log (WHEN: 30m, 2h, 7d or 2026-11-17)
  status [--json]               Show the daemon's state, audit head and sink health
  verify-log [--expect-head SEQ:HASH] [--daemon]
                                Check the audit log's chain (and that an anchored head is present)
  repair                        After an audit failure: cut a partial entry, verify, clear the lock-out
  migrate-log                   Move a version 1 audit log aside and start a keyed (v2) log
  doctor                        Check permissions, key source, socket, sinks and admission setup
  paths                         Show the config, socket, vault, key and log paths

The reason can also come from the BOUNCER_REASON environment variable.
Exit codes: 0 ok, 1 error, 2 usage or missing reason, 3 denied, 4 not found,
5 daemon unreachable or busy, 6 daemon identity mismatch, 7 audit log failed,
8 verification or doctor found problems. `exec` returns the command's own exit code
once the command has started.
";

const NOTICE: &str = "bouncer is provided as is, without warranty of any kind; you are responsible for deciding whether it fits your threat model (see README).";

const EXIT_ERROR: i32 = 1;
const EXIT_USAGE: i32 = 2;
const EXIT_DENIED: i32 = 3;
const EXIT_NOT_FOUND: i32 = 4;
const EXIT_UNREACHABLE: i32 = 5;
const EXIT_IDENTITY: i32 = 6;
const EXIT_AUDIT: i32 = 7;
const EXIT_VERIFY: i32 = 8;

const NEED_REASON: &str = "\
bouncer: a reason is required. Say what you need the secret for, for example:
  bouncer get GITHUB_TOKEN --reason \"open a PR for the docs fix\"
(or set BOUNCER_REASON). The reason is recorded in the audit log.";

const CONFIG_TEMPLATE: &str = r#"# bouncer config. A strict subset of TOML; every key is optional.
# Paths default to the platform locations shown by `bouncer paths`. See the README.

# socket = "/run/bouncer/bouncer.sock"
# socket_mode = "0660"
# socket_group = "bouncer-clients"  # dedicated-user mode: group allowed to reach the socket
# admin_socket = "/run/bouncer/admin.sock"   # if set, set/rm are only accepted here
# server_uid = 999                  # clients: uid the daemon must run as (default: your own)
# user = "bouncer"                  # Linux: start as root, drop to this user (see contrib/)
# allowed_uids = [1000]             # uids that may connect; default: the daemon's own uid
# admin_uids = [999]                # uids that may set/rm; default: the daemon's own uid
# vault = "/var/lib/bouncer/vault.bin"
# key = "/var/lib/bouncer/key"      # or key_credential = "bouncer-key" / key_command = [...]
# audit_log = "/var/lib/bouncer/audit.jsonl"
# audit_fsync = "async"             # or "strict": fsync each entry before answering
# min_reason_len = 8
# require_write_reason = false
# require_attribution = true        # deny get/exec when the caller cannot be attributed
# max_chain_depth = 16              # ancestors recorded per entry (all are walked)
# max_connections = 64
# request_timeout_ms = 5000
# mlock = true
# context_vars = ["T3CODE_THREAD_ID", "CLAUDE_CODE_SESSION_ID", "CODEX_THREAD_ID", "CODEX_SESSION_ID"]

# [[sink]]
# type = "s3"
# endpoint = "https://s3.us-east-1.amazonaws.com"
# bucket = "my-audit-bucket"
# region = "us-east-1"
# prefix = "bouncer"
# access_key_id_file = "/etc/bouncer/s3-key-id"          # mode 0600, or *_credential
# secret_access_key_file = "/etc/bouncer/s3-secret"

# [admission]
# enabled = false
"#;

fn main() {
    let code = match run(std::env::args_os().skip(1).collect()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("bouncer: {e}");
            EXIT_ERROR
        }
    };
    std::process::exit(code);
}

fn usage_err(msg: impl std::fmt::Display) -> Result<i32> {
    eprintln!("bouncer: {msg}\nRun `bouncer help` for usage.");
    Ok(EXIT_USAGE)
}

/// Argument cursor supporting `--flag value` and `--flag=value`.
struct Args {
    items: std::vec::IntoIter<OsString>,
}

impl Args {
    fn next_os(&mut self) -> Option<OsString> {
        self.items.next()
    }

    fn next(&mut self) -> Option<Result<String>> {
        self.items.next().map(|a| {
            a.into_string()
                .map_err(|_| err!("arguments must be valid UTF-8"))
        })
    }

    /// If `arg` is `name` or `name=...`, returns its value.
    fn value(&mut self, arg: &str, names: &[&str]) -> Option<Result<String>> {
        for name in names {
            if arg == *name {
                return Some(
                    self.next()
                        .unwrap_or_else(|| Err(err!("{name} needs a value"))),
                );
            }
            if let Some(v) = arg.strip_prefix(name).and_then(|r| r.strip_prefix('=')) {
                return Some(Ok(v.to_string()));
            }
        }
        None
    }

    /// Only boolean flags from `allowed` are accepted.
    fn flags(&mut self, allowed: &[&str]) -> Result<std::result::Result<Vec<String>, String>> {
        let mut out = Vec::new();
        while let Some(a) = self.next() {
            let a = a?;
            if !allowed.contains(&a.as_str()) {
                return Ok(Err(a));
            }
            out.push(a);
        }
        Ok(Ok(out))
    }
}

fn run(argv: Vec<OsString>) -> Result<i32> {
    let mut args = Args {
        items: argv.into_iter(),
    };
    let (mut config, mut socket) = (None, None);
    let cmd = loop {
        let Some(a) = args.next() else {
            print!("{USAGE}");
            return Ok(EXIT_USAGE);
        };
        let a = a?;
        if let Some(v) = args.value(&a, &["--config"]) {
            config = Some(PathBuf::from(v?));
        } else if let Some(v) = args.value(&a, &["--socket"]) {
            socket = Some(PathBuf::from(v?));
        } else {
            break a;
        }
    };
    let load = || Config::load(config.clone(), socket.clone());
    match cmd.as_str() {
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(0)
        }
        "-V" | "--version" | "version" => {
            println!("bouncer {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        "init" => cmd_init(&load()?),
        "keygen" => {
            println!("{}", *vault::generate_key_hex()?);
            Ok(0)
        }
        "serve" => {
            let mut opts = server::Options::default();
            match args.flags(&["--accept-vault-mismatch"])? {
                Ok(f) => opts.accept_vault_mismatch = !f.is_empty(),
                Err(a) => return usage_err(format!("unexpected argument `{a}`")),
            }
            server::serve(load()?, opts).map(|_| 0)
        }
        "get" => cmd_get(&load()?, args),
        "exec" => cmd_exec(&load()?, args),
        "set" => cmd_set(&load()?, args),
        "rm" => cmd_rm(&load()?, args),
        "ls" => cmd_ls(&load()?, args),
        "log" => cmd_log(&load()?, args),
        "status" => cmd_status(&load()?, args),
        "verify-log" => cmd_verify(&load()?, args),
        "repair" => cmd_repair(&load()?),
        "migrate-log" => cmd_migrate(&load()?),
        "doctor" => doctor::run(&load()?),
        "paths" => {
            let c = load()?;
            println!("config     {}", c.config_file.display());
            println!("socket     {}", c.socket.display());
            println!("vault      {}", c.vault.display());
            match &c.key {
                KeySource::File(p) => println!("key        {}", p.display()),
                KeySource::Credential(n) => println!("key        systemd credential `{n}`"),
                KeySource::Command(a) => println!("key        command `{}`", a.join(" ")),
            }
            println!("audit_log  {}", c.audit_log.display());
            println!("lock       {}", c.lock_path().display());
            Ok(0)
        }
        other => usage_err(format!("unknown command `{}`", escape(other))),
    }
}

fn reason_from(flag: Option<String>) -> Option<String> {
    flag.or_else(|| std::env::var("BOUNCER_REASON").ok())
        .filter(|r| !r.trim().is_empty())
}

fn show_reasoning(resp: &Response) {
    if let Some(r) = &resp.reasoning {
        eprintln!("bouncer: admission: {}", escape(r));
    }
}

/// Sends a request; prints the daemon's error and returns its exit code on failure.
fn call(cfg: &Config, req: &Request) -> std::result::Result<Response, i32> {
    let resp = match proto::call(&cfg.socket, cfg.server_uid, req, Duration::from_secs(150)) {
        Ok(r) => r,
        Err(CallError::Identity(e)) => {
            eprintln!("bouncer: {e}");
            return Err(EXIT_IDENTITY);
        }
        Err(CallError::Unreachable(e)) => {
            eprintln!("bouncer: {e}");
            return Err(EXIT_UNREACHABLE);
        }
    };
    show_reasoning(&resp);
    if resp.ok {
        return Ok(resp);
    }
    let code = resp.code.as_deref().unwrap_or("");
    let msg = resp.error.as_deref().unwrap_or("request failed");
    eprintln!("bouncer: {}", escape(msg));
    Err(match code {
        proto::E_DENIED => EXIT_DENIED,
        proto::E_NOT_FOUND => EXIT_NOT_FOUND,
        proto::E_BAD_REQUEST => EXIT_USAGE,
        proto::E_AUDIT => EXIT_AUDIT,
        proto::E_BUSY => EXIT_UNREACHABLE,
        proto::E_VERIFY => EXIT_VERIFY,
        _ => EXIT_ERROR,
    })
}

fn cmd_init(cfg: &Config) -> Result<i32> {
    let _lock = server::lock_store(cfg)?;
    let (vdir, vname) = util::split_path(&cfg.vault)?;
    let vault_dir = util::Dir::secure(&vdir, true)?;
    if vault_dir.lstat(vname)?.is_some() {
        return Err(err!(
            "a vault already exists at {}; not touching it",
            cfg.vault.display()
        ));
    }
    if std::fs::symlink_metadata(&cfg.audit_log).is_ok_and(|m| m.len() > 0) {
        return Err(err!(
            "an audit log already exists at {}; move it aside first",
            cfg.audit_log.display()
        ));
    }
    match &cfg.key {
        KeySource::File(p) if std::fs::symlink_metadata(p).is_err() => {
            vault::generate_key_file(p)?;
            println!("created key   {}", p.display());
        }
        KeySource::File(p) => println!("using key     {}", p.display()),
        KeySource::Credential(n) => println!("using key     systemd credential `{n}`"),
        KeySource::Command(a) => println!("using key     from `{}`", a.join(" ")),
    }
    let key = vault::load_key(&cfg.key)?;
    let v = Vault {
        generation: 1,
        ..Default::default()
    };
    let bytes = v.encrypt(&key)?;
    let (mut log, _) = audit::AuditLog::open(&cfg.audit_log, vault::chain_key(&key), true)?;
    let mut e = audit::Entry::new("init", &util::hostname());
    e.vault_gen = Some(1);
    e.vault_hash = Some(util::sha256_hex(&bytes));
    log.append(e)?;
    vault_dir.write_atomic(vname, &bytes, 0o600)?;
    println!("created vault {}", cfg.vault.display());
    println!("created log   {}", cfg.audit_log.display());
    if std::fs::symlink_metadata(&cfg.config_file).is_err() {
        util::write_file_atomic(&cfg.config_file, CONFIG_TEMPLATE.as_bytes(), 0o600)?;
        println!("wrote config  {}", cfg.config_file.display());
    }
    println!("\n{NOTICE}");
    println!("Back up the key separately from the vault. Next: bouncer serve");
    Ok(0)
}

fn cmd_get(cfg: &Config, mut args: Args) -> Result<i32> {
    let (mut name, mut reason, mut newline) = (None, None, false);
    while let Some(a) = args.next() {
        let a = a?;
        if let Some(v) = args.value(&a, &["--reason", "-r"]) {
            reason = Some(v?);
        } else if a == "-n" || a == "--newline" {
            newline = true;
        } else if a.starts_with('-') {
            return usage_err(format!("unknown option `{}`", escape(&a)));
        } else if name.replace(a).is_some() {
            return usage_err("get takes exactly one secret name");
        }
    }
    let Some(name) = name else {
        return usage_err("usage: bouncer get NAME --reason TEXT");
    };
    let Some(reason) = reason_from(reason) else {
        eprintln!("{NEED_REASON}");
        return Ok(EXIT_USAGE);
    };
    let resp = match call(cfg, &Request::new(Op::Get, vec![name], reason)) {
        Ok(r) => r,
        Err(code) => return Ok(code),
    };
    let mut out = io::stdout().lock();
    out.write_all(
        resp.values
            .first()
            .map(|v| v.0.as_bytes())
            .unwrap_or_default(),
    )?;
    if newline {
        out.write_all(b"\n")?;
    }
    out.flush()?;
    Ok(0)
}

/// `NAME` -> env var `NAME` if it is a valid variable name, else a sanitised upper-case form.
fn env_name(name: &str) -> String {
    if valid_env_name(name) {
        return name.to_string();
    }
    let mut s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    if s.starts_with(|c: char| c.is_ascii_digit()) {
        s.insert(0, '_');
    }
    s
}

/// `[A-Za-z_][A-Za-z0-9_]*`
fn valid_env_name(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
}

/// Parses `NAME[=VAR]` specs; checks variable names and that no variable is used twice.
fn exec_specs(raw: &[String]) -> std::result::Result<Vec<(String, String)>, String> {
    let mut specs: Vec<(String, String)> = Vec::new();
    for a in raw {
        let (name, var) = match a.split_once('=') {
            Some((n, v)) => (n.to_string(), v.to_string()),
            None => (a.clone(), env_name(a)),
        };
        if !valid_env_name(&var) {
            return Err(format!(
                "`{}` is not a valid environment variable name (use [A-Za-z_][A-Za-z0-9_]*)",
                escape(&var)
            ));
        }
        if let Some((other, _)) = specs.iter().find(|(_, v)| *v == var) {
            if *other != name {
                return Err(format!(
                    "{} and {} would both set ${var}; pick names with NAME=VAR",
                    escape(other),
                    escape(&name)
                ));
            }
            return Err(format!("${var} is given twice"));
        }
        specs.push((name, var));
    }
    Ok(specs)
}

/// The child's pid, for forwarding signals.
static CHILD: AtomicI32 = AtomicI32::new(0);

/// The pid that sent a signal; 0 when the kernel or the terminal generated it.
#[cfg(target_os = "linux")]
unsafe fn sender(info: *const libc::siginfo_t) -> libc::pid_t {
    // SAFETY: the caller passes the kernel's siginfo.
    unsafe { (*info).si_pid() }
}

#[cfg(target_os = "macos")]
unsafe fn sender(info: *const libc::siginfo_t) -> libc::pid_t {
    // SAFETY: the caller passes the kernel's siginfo.
    unsafe { (*info).si_pid }
}

extern "C" fn forward_signal(sig: libc::c_int, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
    let pid = CHILD.load(Ordering::Relaxed);
    // Signals from the terminal (Ctrl-C) already reach the child through its process group;
    // forward only signals another process sent to us.
    // SAFETY: the kernel passes a valid siginfo; kill is async-signal-safe.
    unsafe {
        if pid > 0 && !info.is_null() && sender(info) != 0 {
            libc::kill(pid, sig);
        }
    }
}

fn install_forwarding() {
    // SAFETY: sigaction with a handler that only calls async-signal-safe functions.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = forward_signal as *const () as usize;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

/// After the child exits, output from grandchildren that kept the pipes open is read for at
/// most this long.
const DRAIN: Duration = Duration::from_millis(1000);

fn cmd_exec(cfg: &Config, mut args: Args) -> Result<i32> {
    let mut reason = None;
    let mut raw = Vec::new();
    let mut found_sep = false;
    while let Some(a) = args.next() {
        let a = a?;
        if a == "--" {
            found_sep = true;
            break;
        } else if let Some(v) = args.value(&a, &["--reason", "-r"]) {
            reason = Some(v?);
        } else if a.starts_with('-') {
            return usage_err(format!("unknown option `{}`", escape(&a)));
        } else {
            raw.push(a);
        }
    }
    let cmd: Vec<OsString> = std::iter::from_fn(|| args.next_os()).collect();
    if !found_sep || cmd.is_empty() || raw.is_empty() {
        return usage_err("usage: bouncer exec --reason TEXT NAME[=ENVVAR]... -- CMD [ARGS...]");
    }
    let specs = match exec_specs(&raw) {
        Ok(s) => s,
        Err(e) => return usage_err(e),
    };
    let Some(reason) = reason_from(reason) else {
        eprintln!("{NEED_REASON}");
        return Ok(EXIT_USAGE);
    };
    let names = specs.iter().map(|(n, _)| n.clone()).collect();
    let resp = match call(cfg, &Request::new(Op::Exec, names, reason)) {
        Ok(r) => r,
        Err(code) => return Ok(code),
    };
    if resp.values.len() != specs.len() {
        return Err(err!("daemon returned the wrong number of values"));
    }
    install_forwarding();
    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .envs(
            specs
                .iter()
                .zip(&resp.values)
                .map(|((_, var), v)| (var, &v.0)),
        )
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| err!("cannot run {}: {e}", cmd[0].to_string_lossy()))?;
    CHILD.store(child.id() as i32, Ordering::Relaxed);
    let values: Vec<SecretValue> = resp.values.clone();
    drop(resp);
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    for (pipe, is_err) in [
        (
            child
                .stdout
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
            false,
        ),
        (
            child
                .stderr
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
            true,
        ),
    ] {
        let vals: Vec<Zeroizing<String>> =
            values.iter().map(|v| Zeroizing::new(v.0.clone())).collect();
        let tx = done_tx.clone();
        std::thread::spawn(move || {
            let refs: Vec<&str> = vals.iter().map(|v| v.as_str()).collect();
            if let Some(p) = pipe {
                let r = Redactor::new(&refs);
                let _ = if is_err {
                    r.copy(p, io::stderr())
                } else {
                    r.copy(p, io::stdout())
                };
            }
            let _ = tx.send(());
        });
    }
    drop(done_tx);
    drop(values);
    let status = child.wait()?;
    CHILD.store(0, Ordering::Relaxed);
    let until = std::time::Instant::now() + DRAIN;
    for _ in 0..2 {
        let left = until.saturating_duration_since(std::time::Instant::now());
        if done_rx.recv_timeout(left).is_err() {
            break; // a background process still holds the pipe; stop waiting for it
        }
    }
    Ok(status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)))
}

fn read_value(raw: bool, name: &str) -> Result<SecretValue> {
    if util::isatty(0) {
        eprint!("Value for {} (input hidden): ", escape(name));
        let echo_off = util::echo_off();
        let mut line = Zeroizing::new(String::new());
        let r = io::stdin().lock().read_line(&mut line);
        if echo_off {
            util::echo_restore();
        }
        eprintln!();
        r?;
        return Ok(SecretValue(line.trim_end_matches(['\r', '\n']).to_string()));
    }
    let mut buf = Zeroizing::new(Vec::new());
    io::stdin()
        .take(proto::MAX_VALUE as u64 + 3)
        .read_to_end(&mut buf)?;
    let s = std::str::from_utf8(&buf).map_err(|_| err!("the value must be UTF-8 text"))?;
    let mut v = SecretValue(s.to_string());
    if !raw {
        if v.0.ends_with("\r\n") {
            v.0.truncate(v.0.len() - 2);
        } else if v.0.ends_with('\n') {
            v.0.pop();
        }
    }
    if v.0.len() > proto::MAX_VALUE {
        return Err(err!("values are limited to {} bytes", proto::MAX_VALUE));
    }
    Ok(v)
}

fn cmd_set(cfg: &Config, mut args: Args) -> Result<i32> {
    let (mut name, mut desc, mut reason, mut tags, mut raw) = (None, None, None, vec![], false);
    while let Some(a) = args.next() {
        let a = a?;
        if let Some(v) = args.value(&a, &["--desc", "-d"]) {
            desc = Some(v?);
        } else if let Some(v) = args.value(&a, &["--tag", "-t"]) {
            tags.push(v?);
        } else if let Some(v) = args.value(&a, &["--reason", "-r"]) {
            reason = Some(v?);
        } else if a == "--raw" {
            raw = true;
        } else if a.starts_with('-') {
            return usage_err(format!("unknown option `{}`", escape(&a)));
        } else if name.replace(a).is_some() {
            return usage_err(
                "set takes one name; the value is read from stdin, never from arguments",
            );
        }
    }
    let Some(name) = name else {
        return usage_err("usage: printf %s VALUE | bouncer set NAME [--desc TEXT] [--tag TAG]");
    };
    let reason = reason_from(reason);
    if cfg.require_write_reason && reason.is_none() {
        eprintln!(
            "bouncer: a reason is required for set (require_write_reason = true); pass --reason"
        );
        return Ok(EXIT_USAGE);
    }
    let value = read_value(raw, &name)?;
    if value.0.is_empty() {
        return usage_err("empty value; nothing stored");
    }
    let mut req = Request::new(Op::Set, vec![name.clone()], reason.unwrap_or_default());
    req.value = Some(value);
    req.desc = desc;
    req.tags = tags;
    match call(cfg, &req) {
        Ok(_) => {
            eprintln!("stored {}", escape(&name));
            Ok(0)
        }
        Err(code) => Ok(code),
    }
}

fn cmd_rm(cfg: &Config, mut args: Args) -> Result<i32> {
    let (mut name, mut reason) = (None, None);
    while let Some(a) = args.next() {
        let a = a?;
        if let Some(v) = args.value(&a, &["--reason", "-r"]) {
            reason = Some(v?);
        } else if a.starts_with('-') {
            return usage_err(format!("unknown option `{}`", escape(&a)));
        } else if name.replace(a).is_some() {
            return usage_err("rm takes exactly one secret name");
        }
    }
    let Some(name) = name else {
        return usage_err("usage: bouncer rm NAME [--reason TEXT]");
    };
    let reason = reason_from(reason);
    if cfg.require_write_reason && reason.is_none() {
        eprintln!(
            "bouncer: a reason is required for rm (require_write_reason = true); pass --reason"
        );
        return Ok(EXIT_USAGE);
    }
    let req = Request::new(Op::Rm, vec![name.clone()], reason.unwrap_or_default());
    match call(cfg, &req) {
        Ok(_) => {
            eprintln!("removed {}", escape(&name));
            Ok(0)
        }
        Err(code) => Ok(code),
    }
}

fn cmd_ls(cfg: &Config, mut args: Args) -> Result<i32> {
    let json = match args.flags(&["--json"])? {
        Ok(f) => !f.is_empty(),
        Err(a) => return usage_err(format!("unexpected argument `{}`", escape(&a))),
    };
    let resp = match call(cfg, &Request::new(Op::Ls, vec![], String::new())) {
        Ok(r) => r,
        Err(code) => return Ok(code),
    };
    let mut out = io::stdout().lock();
    if json {
        serde_json::to_writer(&mut out, &resp.list).map_err(|e| err!("{e}"))?;
        writeln!(out)?;
        return Ok(0);
    }
    let width = resp.list.iter().map(|i| i.name.len()).max().unwrap_or(0);
    for i in &resp.list {
        let tags = if i.tags.is_empty() {
            String::new()
        } else {
            format!("[{}] ", escape(&i.tags.join(",")))
        };
        writeln!(
            out,
            "{:width$}  {tags}{}",
            escape(&i.name),
            escape(i.desc.as_deref().unwrap_or(""))
        )?;
    }
    Ok(0)
}

/// Turns `30m` / `2h` / `7d` / `45s` into an absolute timestamp, or checks a date prefix.
fn parse_since(s: &str) -> Result<String> {
    let bad = || {
        err!(
            "--since takes a duration (30m, 2h, 7d) or a UTC date/time (2026-11-17, 2026-11-17T09:30)"
        )
    };
    let mult = match s.as_bytes().last() {
        Some(b's') => Some(1_000i64),
        Some(b'm') => Some(60_000),
        Some(b'h') => Some(3_600_000),
        Some(b'd') => Some(86_400_000),
        _ => None,
    };
    if let Some(mult) = mult {
        let digits = &s[..s.len() - 1];
        if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
            let n: i64 = digits.parse().map_err(|_| bad())?;
            let back = n.checked_mul(mult).ok_or_else(bad)?;
            return Ok(util::rfc3339_ms(util::now_ms().saturating_sub(back).max(0)));
        }
    }
    let b = s.as_bytes();
    let date_like = b.len() >= 10
        && b[..10].iter().enumerate().all(|(i, c)| {
            if i == 4 || i == 7 {
                *c == b'-'
            } else {
                c.is_ascii_digit()
            }
        });
    if date_like {
        return Ok(s.to_string());
    }
    Err(bad())
}

fn cmd_log(cfg: &Config, mut args: Args) -> Result<i32> {
    let (mut since, mut thread, mut name, mut tail, mut json) = (None, None, None, None, false);
    while let Some(a) = args.next() {
        let a = a?;
        if let Some(v) = args.value(&a, &["--since"]) {
            since = Some(parse_since(&v?)?);
        } else if let Some(v) = args.value(&a, &["--thread"]) {
            thread = Some(v?);
        } else if let Some(v) = args.value(&a, &["--name"]) {
            name = Some(v?);
        } else if let Some(v) = args.value(&a, &["--tail"]) {
            tail = Some(
                v?.parse::<usize>()
                    .map_err(|_| err!("--tail takes a number"))?,
            );
        } else if a == "--json" {
            json = true;
        } else {
            return usage_err(format!("unexpected argument `{}`", escape(&a)));
        }
    }
    let file = match util::open_nofollow(&cfg.audit_log) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(err!("cannot read {}: {e}", cfg.audit_log.display())),
    };
    let mut lines: std::collections::VecDeque<(String, serde_json::Value)> = Default::default();
    for line in io::BufReader::new(file).lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(&line)
            .map_err(|_| err!("audit log contains a line that is not JSON"))?;
        if let Some(s) = &since
            && v["ts"].as_str().unwrap_or("") < s.as_str()
        {
            continue;
        }
        if let Some(n) = &name
            && !v["names"]
                .as_array()
                .is_some_and(|a| a.iter().any(|x| x.as_str() == Some(n)))
        {
            continue;
        }
        if let Some(t) = &thread {
            let ctx = &v["attribution"]["context"];
            let hit = ctx.as_object().is_some_and(|c| {
                c.values().any(|x| {
                    x["value"].as_str() == Some(t)
                        || x["other"]
                            .as_array()
                            .is_some_and(|o| o.iter().any(|y| y["value"].as_str() == Some(t)))
                })
            });
            if !hit {
                continue;
            }
        }
        lines.push_back((line, v));
        if let Some(n) = tail
            && lines.len() > n
        {
            lines.pop_front();
        }
    }
    let mut out = io::stdout().lock();
    for (line, v) in &lines {
        if json {
            writeln!(out, "{line}")?;
            continue;
        }
        let s = |x: &serde_json::Value| x.as_str().unwrap_or("").to_string();
        let names: Vec<String> = v["names"]
            .as_array()
            .map(|a| a.iter().map(s).collect())
            .unwrap_or_default();
        let ctx: Vec<String> = v["attribution"]["context"]
            .as_object()
            .map(|c| {
                c.iter()
                    .map(|(k, x)| format!("{k}={}", s(&x["value"])))
                    .collect()
            })
            .unwrap_or_default();
        let exe = v["attribution"]["chain"][0]["exe"]
            .as_str()
            .map(|e| e.rsplit('/').next().unwrap_or(e))
            .unwrap_or("?");
        let mut text = format!(
            "{} #{:<5} {:<6} {:<9} {} pid={}({exe}) {}",
            s(&v["ts"]),
            v["seq"],
            s(&v["op"]),
            s(&v["result"]),
            names.join(","),
            v["peer"]["pid"],
            ctx.join(" "),
        );
        if let Some(w) = v["why"].as_str() {
            text.push_str(&format!(" why: {w}"));
        }
        if let Some(n) = v["note"].as_str() {
            text.push_str(&format!(" note: {n}"));
        }
        // Everything printed is escaped: an entry cannot move the cursor or fake a line.
        writeln!(out, "{}", escape(&text))?;
        if let Some(r) = v["reason"].as_str() {
            writeln!(out, "    reason: {}", escape(r))?;
        }
        if let Some(a) = v["admission"]["reasoning"].as_str() {
            writeln!(out, "    admission: {}", escape(a))?;
        }
    }
    Ok(0)
}

fn cmd_status(cfg: &Config, mut args: Args) -> Result<i32> {
    let json = match args.flags(&["--json"])? {
        Ok(f) => !f.is_empty(),
        Err(a) => return usage_err(format!("unexpected argument `{}`", escape(&a))),
    };
    let resp = match call(cfg, &Request::new(Op::Status, vec![], String::new())) {
        Ok(r) => r,
        Err(code) => return Ok(code),
    };
    let st = resp.status.clone().unwrap_or_default();
    if json {
        println!("{st}");
        return Ok(0);
    }
    let s = |v: &serde_json::Value| {
        escape(
            &v.as_str()
                .map(str::to_string)
                .unwrap_or_else(|| v.to_string()),
        )
        .into_owned()
    };
    println!(
        "daemon     bouncer {} pid {} uid {} since {}",
        s(&st["version"]),
        st["pid"],
        st["uid"],
        s(&st["started"])
    );
    println!(
        "secrets    {} (vault generation {})",
        st["secrets"], st["vault_generation"]
    );
    println!("audit head {}", s(&st["audit"]["head"]));
    println!("log id     {}", s(&st["audit"]["log_id"]));
    if let Some(f) = st["audit"]["failed"].as_str() {
        println!("AUDIT LOG FAILED: {}", escape(f));
    }
    for k in st["sinks"].as_array().into_iter().flatten() {
        println!(
            "sink       {} ({}): delivered seq {}, lag {}, last success {}, last error {}",
            s(&k["name"]),
            s(&k["type"]),
            k["delivered_seq"],
            k["lag"],
            k["last_success"].as_str().unwrap_or("never"),
            k["last_error"]
                .as_str()
                .map(|e| escape(e).into_owned())
                .unwrap_or_else(|| "none".into())
        );
    }
    if st["admission"].is_object() {
        println!(
            "admission  {} {} (on_error = {})",
            s(&st["admission"]["provider"]),
            s(&st["admission"]["model"]),
            s(&st["admission"]["on_error"])
        );
    }
    println!(
        "rejected   {} connection(s) from other uids",
        st["rejected_connections"]
    );
    println!(
        "\nAnchor the head somewhere this host cannot write, then later: bouncer verify-log --expect-head {}",
        s(&st["audit"]["head"])
    );
    Ok(if st["audit"]["failed"].is_string() {
        EXIT_AUDIT
    } else {
        0
    })
}

fn cmd_verify(cfg: &Config, mut args: Args) -> Result<i32> {
    let (mut expect, mut via_daemon) = (None, false);
    while let Some(a) = args.next() {
        let a = a?;
        if let Some(v) = args.value(&a, &["--expect-head"]) {
            expect = Some(v?);
        } else if a == "--daemon" {
            via_daemon = true;
        } else {
            return usage_err(format!("unexpected argument `{}`", escape(&a)));
        }
    }
    if via_daemon {
        let mut req = Request::new(Op::Verify, vec![], String::new());
        req.expect_head = expect;
        return match call(cfg, &req) {
            Ok(r) => {
                let st = r.status.clone().unwrap_or_default();
                println!(
                    "ok: {} entries, head {} (checked by the daemon with the key)",
                    st["entries"],
                    st["head"].as_str().unwrap_or("")
                );
                Ok(0)
            }
            Err(code) => Ok(code),
        };
    }
    let expect = expect.as_deref().map(audit::parse_head).transpose()?;
    let key = vault::load_key(&cfg.key).ok();
    let chain_key = key.as_ref().map(vault::chain_key);
    if chain_key.is_none() {
        eprintln!(
            "bouncer: warning: cannot load the key, so entry MACs are not checked (only the chain's structure). \
             Run as the daemon's user, or use --daemon"
        );
    }
    match audit::verify(
        &cfg.audit_log,
        chain_key.as_deref(),
        expect.as_ref().map(|(s, h)| (*s, h.as_str())),
    ) {
        Ok(r) => {
            println!(
                "ok: {} entries, head {}:{}{}",
                r.entries,
                r.head.seq,
                r.head.mac,
                if r.keyed {
                    ""
                } else {
                    " (structure only, MACs not checked)"
                }
            );
            Ok(0)
        }
        Err(e) => {
            eprintln!("audit log FAILED verification: {e}");
            Ok(EXIT_VERIFY)
        }
    }
}

fn cmd_repair(cfg: &Config) -> Result<i32> {
    let _lock = server::lock_store(cfg)?;
    let key = vault::load_key(&cfg.key).ok();
    if key.is_none() {
        eprintln!("bouncer: warning: cannot load the key; checking the chain's structure only");
    }
    let chain_key = key.as_ref().map(vault::chain_key);
    match audit::repair(&cfg.audit_log, chain_key.as_deref()) {
        Ok(v) => {
            println!(
                "repaired: {} entries, head {}:{}. Start the daemon again.",
                v.entries, v.head.seq, v.head.mac
            );
            Ok(0)
        }
        Err(e) => {
            eprintln!("audit log FAILED verification after repair: {e}");
            Ok(EXIT_VERIFY)
        }
    }
}

fn cmd_migrate(cfg: &Config) -> Result<i32> {
    let _lock = server::lock_store(cfg)?;
    let key = vault::load_key(&cfg.key)?;
    if audit::verify(&cfg.audit_log, Some(&vault::chain_key(&key)), None).is_ok() {
        println!("the audit log is already in the current format");
        return Ok(0);
    }
    let (entries, head) = audit::verify_v1(&cfg.audit_log).map_err(|e| {
        err!(
            "{} is neither a valid v1 nor a v2 log: {e}",
            cfg.audit_log.display()
        )
    })?;
    let mut old = cfg.audit_log.clone().into_os_string();
    old.push(format!(".v1-{}", util::now_ms()));
    let old = PathBuf::from(old);
    std::fs::rename(&cfg.audit_log, &old)?;
    let (vdir, vname) = util::split_path(&cfg.vault)?;
    let vdir = util::Dir::secure(&vdir, true)?;
    let (v, hash) = Vault::load(&vdir, vname, &key)?;
    let (mut log, _) = audit::AuditLog::open(&cfg.audit_log, vault::chain_key(&key), true)?;
    let mut e = audit::Entry::new("init", &util::hostname());
    e.vault_gen = Some(v.generation);
    e.vault_hash = Some(hash);
    e.note = Some(format!(
        "migrated from v1 log {} ({entries} entries, head {head})",
        old.display()
    ));
    log.append(e)?;
    println!(
        "moved the v1 log to {} ({entries} entries, head {head})",
        old.display()
    );
    println!("started a new keyed log at {}", cfg.audit_log.display());
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_names() {
        assert_eq!(env_name("GITHUB_TOKEN"), "GITHUB_TOKEN");
        assert_eq!(env_name("work/aws.key-1"), "WORK_AWS_KEY_1");
        assert_eq!(env_name("1password"), "_1PASSWORD");
        assert!(
            valid_env_name("_A1")
                && !valid_env_name("1A")
                && !valid_env_name("")
                && !valid_env_name("A-B")
        );
    }

    #[test]
    fn exec_spec_validation() {
        let s = |v: &[&str]| exec_specs(&v.iter().map(|x| x.to_string()).collect::<Vec<_>>());
        assert_eq!(
            s(&["A", "b/c=X"]).unwrap(),
            vec![("A".into(), "A".into()), ("b/c".into(), "X".into())]
        );
        assert!(s(&["A=1BAD"]).is_err());
        assert!(s(&["A="]).is_err());
        assert!(s(&["A=X Y"]).is_err());
        // work/db and work.db both map to WORK_DB.
        assert!(s(&["work/db", "work.db"]).unwrap_err().contains("WORK_DB"));
        assert!(s(&["A=X", "B=X"]).is_err());
    }

    #[test]
    fn since() {
        assert!(parse_since("30m").unwrap() < util::rfc3339_ms(util::now_ms()));
        assert_eq!(parse_since("2026-11-17").unwrap(), "2026-11-17");
        assert!(parse_since("yesterday").is_err());
        assert!(parse_since("m").is_err());
        assert!(parse_since("-5m").is_err());
        // Overflow is an error, not a panic.
        assert!(parse_since("999999999999999999d").is_err());
        assert!(parse_since("9223372036854775807s").is_err());
        assert!(parse_since("5é").is_err());
    }
}
