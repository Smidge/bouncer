use std::ffi::OsString;
use std::fs;
use std::io::{self, BufRead, Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use bouncer::config::Config;
use bouncer::proto::{self, Op, Request, Response};
use bouncer::redact::Redactor;
use bouncer::util::{self, Error, Result};
use bouncer::vault::{self, Vault};
use bouncer::{audit, err, server};

const USAGE: &str = "\
bouncer: a local secret store for agents. Every read needs a reason and is audit-logged.

Usage: bouncer [--config FILE] [--socket PATH] <command>

Commands:
  init                          Create the key, an empty vault and a config template
  serve                         Run the daemon (holds decrypted secrets in memory)
  get NAME --reason TEXT [-n]   Print a secret to stdout (-n adds a trailing newline)
  exec --reason TEXT NAME[=ENV]... -- CMD [ARGS...]
                                Run CMD with secrets in its environment; secret values
                                in its stdout/stderr are replaced with [REDACTED:NAME]
  set NAME [--desc TEXT] [--tag TAG]... [--raw]
                                Store a secret read from stdin (one trailing newline is
                                stripped unless --raw)
  rm NAME                       Delete a secret
  ls [--json]                   List secret names and metadata (never values)
  log [--since WHEN] [--thread ID] [--name NAME] [--tail N] [--json]
                                Show the local audit log (WHEN: 30m, 2h, 7d or 2026-11-17)
  verify-log                    Check the audit log's hash chain
  paths                         Show the config, socket, vault, key and log paths

The reason can also come from the BOUNCER_REASON environment variable.
Exit codes: 0 ok, 1 error, 2 usage or missing reason, 3 denied, 4 not found, 5 daemon unreachable.
";

const EXIT_USAGE: i32 = 2;
const EXIT_DENIED: i32 = 3;
const EXIT_NOT_FOUND: i32 = 4;
const EXIT_UNREACHABLE: i32 = 5;

const NEED_REASON: &str = "\
bouncer: a reason is required. Say what you need the secret for, for example:
  bouncer get GITHUB_TOKEN --reason \"open a PR for the docs fix\"
(or set BOUNCER_REASON). The reason is recorded in the audit log.";

const CONFIG_TEMPLATE: &str = r#"# bouncer config. A strict subset of TOML; every key is optional.
# Paths default to the platform locations shown by `bouncer paths`.

# socket = "/run/bouncer/bouncer.sock"
# socket_mode = "0600"            # use "0666" with allowed_uids when the daemon has its own user
# allowed_uids = [1000]           # uids that may connect; default: the daemon's own uid
# vault = "/var/lib/bouncer/vault.bin"
# key = "/etc/bouncer/key"
# audit_log = "/var/lib/bouncer/audit.jsonl"
# audit_fsync = "async"           # or "strict": fsync each entry before releasing a secret
# min_reason_len = 8
# max_chain_depth = 16
# context_vars = ["T3CODE_THREAD_ID", "CLAUDE_CODE_SESSION_ID", "CODEX_THREAD_ID", "CODEX_SESSION_ID"]

# [s3]
# endpoint = "https://s3.us-east-1.amazonaws.com"
# bucket = "my-audit-bucket"
# region = "us-east-1"
# prefix = "bouncer"
# path_style = true
# access_key_id_secret = "AUDIT_S3_ACCESS_KEY_ID"          # names of secrets in this vault
# secret_access_key_secret = "AUDIT_S3_SECRET_ACCESS_KEY"
"#;

fn main() {
    let code = match run(std::env::args_os().skip(1).collect()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("bouncer: {e}");
            1
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
        "serve" => server::serve(load()?).map(|_| 0),
        "get" => cmd_get(&load()?, args),
        "exec" => cmd_exec(&load()?, args),
        "set" => cmd_set(&load()?, args),
        "rm" => cmd_rm(&load()?, args),
        "ls" => cmd_ls(&load()?, args),
        "log" => cmd_log(&load()?, args),
        "verify-log" => cmd_verify(&load()?),
        "paths" => {
            let c = load()?;
            println!("config     {}", c.config_file.display());
            println!("socket     {}", c.socket.display());
            println!("vault      {}", c.vault.display());
            println!("key        {}", c.key.display());
            println!("audit_log  {}", c.audit_log.display());
            Ok(0)
        }
        other => usage_err(format!("unknown command `{other}`")),
    }
}

fn reason_from(flag: Option<String>) -> Option<String> {
    flag.or_else(|| std::env::var("BOUNCER_REASON").ok())
        .filter(|r| !r.trim().is_empty())
}

/// Sends a request; prints the daemon's error and returns its exit code on failure.
fn call(cfg: &Config, req: &Request) -> std::result::Result<Response, i32> {
    let resp = match proto::call(&cfg.socket, req) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("bouncer: {e}");
            return Err(EXIT_UNREACHABLE);
        }
    };
    if resp.ok {
        return Ok(resp);
    }
    let code = resp.code.as_deref().unwrap_or("");
    let msg = resp.error.as_deref().unwrap_or("request failed");
    eprintln!("bouncer: {msg}");
    Err(match code {
        proto::E_DENIED => EXIT_DENIED,
        proto::E_NOT_FOUND => EXIT_NOT_FOUND,
        proto::E_BAD_REQUEST => EXIT_USAGE,
        _ => 1,
    })
}

fn cmd_init(cfg: &Config) -> Result<i32> {
    if cfg.vault.exists() {
        return Err(err!(
            "a vault already exists at {}; not touching it",
            cfg.vault.display()
        ));
    }
    for p in [&cfg.key, &cfg.vault, &cfg.audit_log] {
        if let Some(d) = p.parent() {
            util::ensure_dir(d, 0o700)?;
        }
    }
    if cfg.key.exists() {
        println!("using existing key {}", cfg.key.display());
    } else {
        vault::generate_key(&cfg.key)?;
        println!("created key   {}", cfg.key.display());
    }
    let key = vault::load_key(&cfg.key)?;
    Vault::default().save(&cfg.vault, &key)?;
    println!("created vault {}", cfg.vault.display());
    if !cfg.config_file.exists() {
        if let Some(d) = cfg.config_file.parent() {
            util::ensure_dir(d, 0o700)?;
        }
        util::write_atomic(&cfg.config_file, CONFIG_TEMPLATE.as_bytes(), 0o600)?;
        println!("wrote config  {}", cfg.config_file.display());
    }
    println!("\nBack up the key file separately from the vault. Next: bouncer serve");
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
            return usage_err(format!("unknown option `{a}`"));
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
            .map(String::as_bytes)
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
    let ok = name
        .bytes()
        .enumerate()
        .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()));
    if ok {
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

fn cmd_exec(cfg: &Config, mut args: Args) -> Result<i32> {
    let mut reason = None;
    let mut specs: Vec<(String, String)> = Vec::new();
    let mut found_sep = false;
    while let Some(a) = args.next() {
        let a = a?;
        if a == "--" {
            found_sep = true;
            break;
        } else if let Some(v) = args.value(&a, &["--reason", "-r"]) {
            reason = Some(v?);
        } else if a.starts_with('-') {
            return usage_err(format!("unknown option `{a}`"));
        } else {
            let (name, var) = match a.split_once('=') {
                Some((n, v)) => (n.to_string(), v.to_string()),
                None => (a.clone(), env_name(&a)),
            };
            specs.push((name, var));
        }
    }
    let cmd: Vec<OsString> = std::iter::from_fn(|| args.next_os()).collect();
    if !found_sep || cmd.is_empty() || specs.is_empty() {
        return usage_err("usage: bouncer exec --reason TEXT NAME[=ENVVAR]... -- CMD [ARGS...]");
    }
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
    let secrets: Vec<(String, String)> = specs
        .iter()
        .zip(&resp.values)
        .map(|((n, _), v)| (n.clone(), v.clone()))
        .collect();
    let mut child = Command::new(&cmd[0])
        .args(&cmd[1..])
        .envs(specs.iter().zip(&resp.values).map(|((_, var), v)| (var, v)))
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| err!("cannot run {}: {e}", cmd[0].to_string_lossy()))?;
    let (out, errp) = (child.stdout.take(), child.stderr.take());
    let s2 = secrets.clone();
    let t_out =
        std::thread::spawn(move || out.map(|o| Redactor::new(&secrets).copy(o, io::stdout())));
    let t_err = std::thread::spawn(move || errp.map(|e| Redactor::new(&s2).copy(e, io::stderr())));
    let status = child.wait()?;
    let _ = t_out.join();
    let _ = t_err.join();
    Ok(status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)))
}

fn read_value(raw: bool, name: &str) -> Result<String> {
    if util::isatty(0) {
        eprint!("Value for {name} (input hidden): ");
        let echo_off = util::set_echo(false);
        let mut line = String::new();
        let r = io::stdin().lock().read_line(&mut line);
        if echo_off {
            util::set_echo(true);
        }
        eprintln!();
        r?;
        return Ok(line.trim_end_matches(['\r', '\n']).to_string());
    }
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf)?;
    let mut s = String::from_utf8(buf).map_err(|_| err!("the value must be UTF-8 text"))?;
    if !raw {
        if s.ends_with("\r\n") {
            s.truncate(s.len() - 2);
        } else if s.ends_with('\n') {
            s.pop();
        }
    }
    Ok(s)
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
            return usage_err(format!("unknown option `{a}`"));
        } else if name.replace(a).is_some() {
            return usage_err(
                "set takes one name; the value is read from stdin, never from arguments",
            );
        }
    }
    let Some(name) = name else {
        return usage_err("usage: echo -n VALUE | bouncer set NAME [--desc TEXT] [--tag TAG]");
    };
    let value = read_value(raw, &name)?;
    if value.is_empty() {
        return usage_err("empty value; nothing stored");
    }
    let mut req = Request::new(
        Op::Set,
        vec![name.clone()],
        reason_from(reason).unwrap_or_default(),
    );
    req.value = Some(value);
    req.desc = desc;
    req.tags = tags;
    match call(cfg, &req) {
        Ok(_) => {
            eprintln!("stored {name}");
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
            return usage_err(format!("unknown option `{a}`"));
        } else if name.replace(a).is_some() {
            return usage_err("rm takes exactly one secret name");
        }
    }
    let Some(name) = name else {
        return usage_err("usage: bouncer rm NAME");
    };
    let req = Request::new(
        Op::Rm,
        vec![name.clone()],
        reason_from(reason).unwrap_or_default(),
    );
    match call(cfg, &req) {
        Ok(_) => {
            eprintln!("removed {name}");
            Ok(0)
        }
        Err(code) => Ok(code),
    }
}

fn cmd_ls(cfg: &Config, mut args: Args) -> Result<i32> {
    let mut json = false;
    while let Some(a) = args.next() {
        match a?.as_str() {
            "--json" => json = true,
            other => return usage_err(format!("unexpected argument `{other}`")),
        }
    }
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
            format!("[{}] ", i.tags.join(","))
        };
        writeln!(
            out,
            "{:width$}  {tags}{}",
            i.name,
            i.desc.as_deref().unwrap_or("")
        )?;
    }
    Ok(0)
}

/// Turns `30m` / `2h` / `7d` / `45s` into an absolute timestamp, or checks a date prefix.
fn parse_since(s: &str) -> Result<String> {
    let unit = s.chars().last().unwrap_or(' ');
    let mult = match unit {
        's' => Some(1_000),
        'm' => Some(60_000),
        'h' => Some(3_600_000),
        'd' => Some(86_400_000),
        _ => None,
    };
    if let Some(mult) = mult
        && let Ok(n) = s[..s.len() - 1].parse::<i64>()
    {
        return Ok(util::rfc3339_ms(util::now_ms() - n * mult));
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
    Err(err!(
        "--since takes a duration (30m, 2h, 7d) or a UTC date/time (2026-11-17, 2026-11-17T09:30)"
    ))
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
            return usage_err(format!("unexpected argument `{a}`"));
        }
    }
    let data = match fs::read_to_string(&cfg.audit_log) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(err!("cannot read {}: {e}", cfg.audit_log.display())),
    };
    let mut lines: Vec<(&str, serde_json::Value)> = Vec::new();
    for line in data.lines().filter(|l| !l.is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line)
            .map_err(|_| Error("audit log contains a line that is not JSON".into()))?;
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
        if let Some(t) = &thread
            && !v["context"]
                .as_object()
                .is_some_and(|c| c.values().any(|x| x["value"].as_str() == Some(t)))
        {
            continue;
        }
        lines.push((line, v));
    }
    let skip = tail.map_or(0, |n| lines.len().saturating_sub(n));
    let mut out = io::stdout().lock();
    for (line, v) in &lines[skip..] {
        if json {
            writeln!(out, "{line}")?;
            continue;
        }
        let names: Vec<&str> = v["names"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        let ctx: Vec<String> = v["context"]
            .as_object()
            .map(|c| {
                c.iter()
                    .map(|(k, x)| format!("{k}={}", x["value"].as_str().unwrap_or("")))
                    .collect()
            })
            .unwrap_or_default();
        let exe = v["chain"][0]["exe"]
            .as_str()
            .map(|e| e.rsplit('/').next().unwrap_or(e))
            .unwrap_or("?");
        let result = v["result"].as_str().unwrap_or("?");
        writeln!(
            out,
            "{} #{:<5} {:<4} {:<9} {} pid={}({exe}) {}{}\n    reason: {}",
            v["ts"].as_str().unwrap_or("?"),
            v["seq"],
            v["op"].as_str().unwrap_or("?"),
            result,
            names.join(","),
            v["peer"]["pid"],
            ctx.join(" "),
            v["why"]
                .as_str()
                .map(|w| format!(" why: {w}"))
                .unwrap_or_default(),
            v["reason"].as_str().unwrap_or(""),
        )?;
    }
    Ok(0)
}

fn cmd_verify(cfg: &Config) -> Result<i32> {
    match audit::verify(&cfg.audit_log) {
        Ok(r) => {
            println!(
                "ok: {} entries, last seq {}, head {}",
                r.entries, r.last_seq, r.last_hash
            );
            Ok(0)
        }
        Err(e) => {
            eprintln!("audit log FAILED verification: {e}");
            Ok(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_names() {
        assert_eq!(env_name("GITHUB_TOKEN"), "GITHUB_TOKEN");
        assert_eq!(env_name("work/aws.key-1"), "WORK_AWS_KEY_1");
        assert_eq!(env_name("1password"), "_1PASSWORD");
    }

    #[test]
    fn since() {
        assert!(parse_since("30m").unwrap() < util::rfc3339_ms(util::now_ms()));
        assert_eq!(parse_since("2026-11-17").unwrap(), "2026-11-17");
        assert!(parse_since("yesterday").is_err());
        assert!(parse_since("m").is_err());
    }
}
