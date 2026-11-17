//! Configuration: default paths plus a small config file.
//!
//! The file format is a strict subset of TOML: top-level keys, `[table]` headers, `[[sink]]`
//! arrays of tables, string, integer, boolean and single-line array values, `#` comments.
//! Parsing that subset takes ~120 lines, while the `toml` crate would add several
//! dependencies for no gain here.

use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::err;
use crate::util::{self, Result};

pub const DEFAULT_CONTEXT_VARS: &[&str] = &[
    "T3CODE_THREAD_ID",
    "CLAUDE_CODE_SESSION_ID",
    "CODEX_THREAD_ID",
    "CODEX_SESSION_ID",
];

#[derive(Clone, Debug, PartialEq)]
pub enum FsyncMode {
    /// A background thread fsyncs the audit log shortly after each append (default).
    Async,
    /// Fsync the audit log before answering.
    Strict,
}

/// Where a credential (sink token, API key) comes from. Never the vault: anything in the
/// vault can be read by clients.
#[derive(Clone, Debug, PartialEq)]
pub enum SecretRef {
    /// A file, mode 0600/0400, owned by the daemon's user or root.
    File(PathBuf),
    /// A systemd credential: `$CREDENTIALS_DIRECTORY/<name>`.
    Credential(String),
}

impl SecretRef {
    pub fn path(&self) -> Result<PathBuf> {
        match self {
            SecretRef::File(p) => Ok(p.clone()),
            SecretRef::Credential(name) => {
                let dir = env::var_os("CREDENTIALS_DIRECTORY").ok_or_else(|| {
                    err!("credential `{name}` needs $CREDENTIALS_DIRECTORY (set by systemd LoadCredential=)")
                })?;
                Ok(Path::new(&dir).join(name))
            }
        }
    }

    /// Reads the credential, trimming surrounding whitespace. Uses the copy read by
    /// `preload` (before a privilege drop) if there is one.
    pub fn load(&self) -> Result<zeroize::Zeroizing<String>> {
        let pre = PRELOADED.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, v)) = pre.iter().find(|(r, _)| r == self) {
            return Ok(v.clone());
        }
        drop(pre);
        self.read()
    }

    /// Reads the credential now and keeps it in memory for later `load` calls.
    pub fn preload(&self) -> Result<()> {
        let v = self.read()?;
        PRELOADED
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((self.clone(), v));
        Ok(())
    }

    fn read(&self) -> Result<zeroize::Zeroizing<String>> {
        let path = self.path()?;
        let bytes = match self {
            SecretRef::File(_) => util::read_secret_file(&path, 64 * 1024)?,
            SecretRef::Credential(_) => util::read_credential_file(&path, 64 * 1024)?,
        };
        let s = std::str::from_utf8(&bytes)
            .map_err(|_| err!("{} is not UTF-8 text", path.display()))?;
        let s = zeroize::Zeroizing::new(s.trim().to_string());
        if s.is_empty() {
            return Err(err!("{} is empty", path.display()));
        }
        Ok(s)
    }

    pub fn describe(&self) -> String {
        match self {
            SecretRef::File(p) => p.display().to_string(),
            SecretRef::Credential(n) => format!("systemd credential `{n}`"),
        }
    }
}

type Preloaded = Vec<(SecretRef, zeroize::Zeroizing<String>)>;
static PRELOADED: std::sync::Mutex<Preloaded> = std::sync::Mutex::new(Vec::new());

/// Where the vault key comes from.
#[derive(Clone, Debug, PartialEq)]
pub enum KeySource {
    File(PathBuf),
    Credential(String),
    /// Runs a command (no shell) and reads the key from its stdout, e.g. the macOS Keychain.
    Command(Vec<String>),
}

#[derive(Clone, Debug)]
pub struct S3Config {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub prefix: String,
    pub path_style: bool,
    pub access_key_id: SecretRef,
    pub secret_access_key: SecretRef,
    /// Send `If-None-Match: *` so existing objects are never overwritten.
    pub conditional_put: bool,
}

#[derive(Clone, Debug)]
pub struct InfluxConfig {
    pub endpoint: String,
    pub org: String,
    pub bucket: String,
    pub token: SecretRef,
    pub measurement: String,
}

#[derive(Clone, Debug)]
pub struct HttpConfig {
    pub url: String,
    pub hmac_secret: Option<SecretRef>,
}

#[derive(Clone, Debug)]
pub struct SyslogConfig {
    pub socket: PathBuf,
    pub facility: u8,
}

#[derive(Clone, Debug)]
pub enum SinkKind {
    S3(S3Config),
    File { path: PathBuf },
    Influx(InfluxConfig),
    Http(HttpConfig),
    Syslog(SyslogConfig),
}

impl SinkKind {
    pub fn type_name(&self) -> &'static str {
        match self {
            SinkKind::S3(_) => "s3",
            SinkKind::File { .. } => "file",
            SinkKind::Influx(_) => "influxdb",
            SinkKind::Http(_) => "http",
            SinkKind::Syslog(_) => "syslog",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SinkConfig {
    pub name: String,
    pub kind: SinkKind,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Provider {
    Anthropic,
    OpenAi,
}

#[derive(Clone, Debug)]
pub struct AdmissionConfig {
    pub provider: Provider,
    pub endpoint: String,
    pub model: String,
    pub api_key: SecretRef,
    pub timeout: Duration,
    /// What to do when the model cannot be reached or answers badly.
    pub on_error_allow: bool,
    pub system_prompt_file: Option<PathBuf>,
    pub cache_ttl: Duration,
    /// Recent requests from the same thread to include as context.
    pub history: usize,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub config_file: PathBuf,
    pub socket: PathBuf,
    pub socket_mode: u32,
    pub socket_group: Option<String>,
    pub admin_socket: Option<PathBuf>,
    /// The uid the client expects the daemon to run as.
    pub server_uid: u32,
    /// When `serve` starts as root (Linux): the user to drop to.
    pub user: Option<String>,
    pub vault: PathBuf,
    pub key: KeySource,
    pub audit_log: PathBuf,
    pub audit_fsync: FsyncMode,
    pub context_vars: Vec<String>,
    pub min_reason_len: usize,
    pub require_write_reason: bool,
    pub max_chain_depth: usize,
    pub require_attribution: bool,
    pub allowed_uids: Vec<u32>,
    pub admin_uids: Vec<u32>,
    pub max_connections: usize,
    pub request_timeout: Duration,
    pub mlock: bool,
    pub deny_debugger: bool,
    pub sinks: Vec<SinkConfig>,
    pub admission: Option<AdmissionConfig>,
    /// allowed_uids / admin_uids / server_uid were not set in the file (they default to the
    /// daemon's uid, which changes after a privilege drop).
    uid_defaults: (bool, bool, bool),
}

fn home() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| "/".into())
}

fn xdg(var: &str, fallback: &str) -> PathBuf {
    match env::var_os(var) {
        Some(v) if Path::new(&v).is_absolute() => PathBuf::from(v),
        _ => home().join(fallback),
    }
}

struct Defaults {
    config_dir: PathBuf,
    data_dir: PathBuf,
    socket: PathBuf,
}

fn defaults() -> Defaults {
    if let Some(h) = env::var_os("BOUNCER_HOME") {
        let h = PathBuf::from(h);
        return Defaults {
            config_dir: h.clone(),
            data_dir: h.clone(),
            socket: h.join("bouncer.sock"),
        };
    }
    if cfg!(target_os = "macos") {
        let d = home().join("Library/Application Support/bouncer");
        return Defaults {
            config_dir: d.clone(),
            data_dir: d.clone(),
            socket: d.join("bouncer.sock"),
        };
    }
    let data_dir = xdg("XDG_DATA_HOME", ".local/share").join("bouncer");
    // Never a predictable path in /tmp: without XDG_RUNTIME_DIR the socket lives in the
    // private data directory.
    let socket = match env::var_os("XDG_RUNTIME_DIR") {
        Some(r) if Path::new(&r).is_absolute() => PathBuf::from(r).join("bouncer/bouncer.sock"),
        _ => data_dir.join("bouncer.sock"),
    };
    Defaults {
        config_dir: xdg("XDG_CONFIG_HOME", ".config").join("bouncer"),
        data_dir,
        socket,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    List(Vec<String>),
}

pub type Table = BTreeMap<String, Value>;

/// A parsed config file.
#[derive(Debug, Default)]
pub struct Doc {
    pub root: Table,
    pub tables: BTreeMap<String, Table>,
    pub arrays: BTreeMap<String, Vec<Table>>,
}

enum Cur {
    Root,
    Table(String),
    Array(String),
}

/// Parses the TOML subset.
pub fn parse_toml(src: &str) -> Result<Doc> {
    let mut doc = Doc::default();
    let mut cur = Cur::Root;
    for (i, raw) in src.lines().enumerate() {
        let lineno = i + 1;
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("[[") {
            let name = rest
                .strip_suffix("]]")
                .ok_or_else(|| err!("config line {lineno}: bad array-of-tables header"))?
                .trim()
                .to_string();
            doc.arrays
                .entry(name.clone())
                .or_default()
                .push(Table::new());
            cur = Cur::Array(name);
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let name = rest
                .strip_suffix(']')
                .ok_or_else(|| err!("config line {lineno}: bad table header"))?
                .trim()
                .to_string();
            if doc.tables.insert(name.clone(), Table::new()).is_some() {
                return Err(err!("config line {lineno}: table [{name}] defined twice"));
            }
            cur = Cur::Table(name);
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| err!("config line {lineno}: expected key = value"))?;
        let value = parse_value(v.trim()).map_err(|e| err!("config line {lineno}: {e}"))?;
        let table = match &cur {
            Cur::Root => &mut doc.root,
            Cur::Table(n) => doc.tables.get_mut(n).expect("inserted above"),
            Cur::Array(n) => doc
                .arrays
                .get_mut(n)
                .and_then(|a| a.last_mut())
                .expect("inserted above"),
        };
        let key = k.trim().to_string();
        if table.insert(key.clone(), value).is_some() {
            return Err(err!("config line {lineno}: `{key}` set twice"));
        }
    }
    Ok(doc)
}

fn strip_comment(line: &str) -> &str {
    let (mut in_str, mut escaped) = (false, false);
    for (i, c) in line.char_indices() {
        if in_str {
            in_str = !(c == '"' && !escaped);
            escaped = c == '\\' && !escaped;
        } else if c == '"' {
            in_str = true;
        } else if c == '#' {
            return &line[..i];
        }
    }
    line
}

fn parse_string(s: &str) -> std::result::Result<(String, &str), String> {
    let body = s.strip_prefix('"').ok_or("expected a string")?;
    let mut out = String::new();
    let mut chars = body.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Ok((out, &body[i + 1..])),
            '\\' => match chars.next().map(|(_, c)| c) {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                _ => return Err("unsupported escape in string".into()),
            },
            c => out.push(c),
        }
    }
    Err("unterminated string".into())
}

fn parse_value(v: &str) -> std::result::Result<Value, String> {
    if v.starts_with('"') {
        let (s, rest) = parse_string(v)?;
        if !rest.trim().is_empty() {
            return Err("trailing characters after string".into());
        }
        return Ok(Value::Str(s));
    }
    if let Some(inner) = v.strip_prefix('[') {
        let mut rest = inner.trim_start();
        let mut items = Vec::new();
        loop {
            if let Some(r) = rest.strip_prefix(']') {
                if !r.trim().is_empty() {
                    return Err("trailing characters after array".into());
                }
                return Ok(Value::List(items));
            }
            let r = if rest.starts_with('"') {
                let (s, r) = parse_string(rest)?;
                items.push(s);
                r
            } else {
                // Bare item (e.g. a number): kept as its text.
                let end = rest.find([',', ']']).ok_or("unterminated array")?;
                items.push(rest[..end].trim().to_string());
                &rest[end..]
            };
            rest = r.trim_start();
            rest = rest.strip_prefix(',').unwrap_or(rest).trim_start();
        }
    }
    match v {
        "true" => Ok(Value::Bool(true)),
        "false" => Ok(Value::Bool(false)),
        _ => v
            .replace('_', "")
            .parse()
            .map(Value::Int)
            .map_err(|_| format!("cannot parse value `{v}`")),
    }
}

/// Typed access to one table, reporting unknown keys at the end.
struct Tbl {
    what: String,
    map: Table,
}

impl Tbl {
    fn new(what: impl Into<String>, map: Table) -> Tbl {
        Tbl {
            what: what.into(),
            map,
        }
    }

    fn e(&self, k: &str, msg: &str) -> util::Error {
        if self.what.is_empty() {
            err!("`{k}` {msg}")
        } else {
            err!("{}: `{k}` {msg}", self.what)
        }
    }

    fn str(&mut self, k: &str) -> Result<Option<String>> {
        match self.map.remove(k) {
            None => Ok(None),
            Some(Value::Str(s)) => Ok(Some(s)),
            Some(_) => Err(self.e(k, "must be a string")),
        }
    }

    fn req(&mut self, k: &str) -> Result<String> {
        self.str(k)?.ok_or_else(|| self.e(k, "is required"))
    }

    fn bool(&mut self, k: &str, default: bool) -> Result<bool> {
        match self.map.remove(k) {
            None => Ok(default),
            Some(Value::Bool(b)) => Ok(b),
            Some(_) => Err(self.e(k, "must be true or false")),
        }
    }

    fn int(&mut self, k: &str, default: u64) -> Result<u64> {
        match self.map.remove(k) {
            None => Ok(default),
            Some(Value::Int(i)) if i >= 0 => Ok(i as u64),
            Some(_) => Err(self.e(k, "must be a non-negative integer")),
        }
    }

    fn list(&mut self, k: &str) -> Result<Option<Vec<String>>> {
        match self.map.remove(k) {
            None => Ok(None),
            Some(Value::List(l)) => Ok(Some(l)),
            Some(_) => Err(self.e(k, "must be a list, e.g. [\"a\", \"b\"]")),
        }
    }

    fn uids(&mut self, k: &str) -> Result<Option<Vec<u32>>> {
        let Some(items) = self.list(k)? else {
            return Ok(None);
        };
        items
            .iter()
            .map(|s| {
                s.parse()
                    .map_err(|_| self.e(k, &format!("has a bad uid `{s}`")))
            })
            .collect::<Result<_>>()
            .map(Some)
    }

    /// `<base>_file = "/path"` or `<base>_credential = "name"`.
    fn secret(&mut self, base: &str) -> Result<Option<SecretRef>> {
        let file = self.str(&format!("{base}_file"))?;
        let cred = self.str(&format!("{base}_credential"))?;
        match (file, cred) {
            (Some(_), Some(_)) => Err(self.e(
                base,
                &format!("set either {base}_file or {base}_credential, not both"),
            )),
            (Some(f), None) => Ok(Some(SecretRef::File(f.into()))),
            (None, Some(c)) => {
                if c.is_empty() || c.contains('/') {
                    return Err(self.e(&format!("{base}_credential"), "must be a plain name"));
                }
                Ok(Some(SecretRef::Credential(c)))
            }
            (None, None) => Ok(None),
        }
    }

    fn req_secret(&mut self, base: &str) -> Result<SecretRef> {
        self.secret(base)?.ok_or_else(|| {
            self.e(
                base,
                &format!("is required: set {base}_file or {base}_credential"),
            )
        })
    }

    /// An http(s) URL; plain http only with `allow_insecure_http = true`.
    fn url(&mut self, k: &str, default: Option<&str>, insecure_ok: bool) -> Result<String> {
        let u = match (self.str(k)?, default) {
            (Some(u), _) => u,
            (None, Some(d)) => d.to_string(),
            (None, None) => return Err(self.e(k, "is required")),
        };
        check_url(&u, insecure_ok).map_err(|m| self.e(k, &m))?;
        Ok(u.trim_end_matches('/').to_string())
    }

    fn done(self) -> Result<()> {
        if self.map.is_empty() {
            return Ok(());
        }
        let keys: Vec<_> = self.map.keys().cloned().collect();
        let place = if self.what.is_empty() {
            String::new()
        } else {
            format!(" in {}", self.what)
        };
        Err(err!("unknown config key(s){place}: {}", keys.join(", ")))
    }
}

/// Requires https unless plain http is explicitly allowed.
pub fn check_url(u: &str, insecure_ok: bool) -> std::result::Result<(), String> {
    if let Some(rest) = u.strip_prefix("https://") {
        if rest.is_empty() {
            return Err("has no host".into());
        }
        return Ok(());
    }
    if u.starts_with("http://") {
        if insecure_ok {
            return Ok(());
        }
        return Err("must use https:// (set allow_insecure_http = true to allow http://)".into());
    }
    Err("must start with https://".into())
}

fn parse_mode(s: &str, k: &str) -> Result<u32> {
    let m = u32::from_str_radix(s, 8).map_err(|_| err!("{k} must be octal, e.g. \"0660\""))?;
    if m & !0o777 != 0 || m & 0o600 != 0o600 {
        return Err(err!("{k} must be like \"0600\" or \"0660\""));
    }
    Ok(m)
}

fn default_syslog_socket() -> PathBuf {
    if cfg!(target_os = "macos") {
        "/var/run/syslog".into()
    } else {
        "/dev/log".into()
    }
}

fn facility(name: &str) -> Option<u8> {
    Some(match name {
        "kern" => 0,
        "user" => 1,
        "daemon" => 3,
        "auth" => 4,
        "authpriv" => 10,
        "local0" => 16,
        "local1" => 17,
        "local2" => 18,
        "local3" => 19,
        "local4" => 20,
        "local5" => 21,
        "local6" => 22,
        "local7" => 23,
        _ => return None,
    })
}

fn parse_sink(t: &mut Tbl, kind: &str) -> Result<SinkKind> {
    // Only the HTTP sinks know `allow_insecure_http`; elsewhere it is an unknown key.
    let insecure = match kind {
        "s3" | "influxdb" | "http" => t.bool("allow_insecure_http", false)?,
        _ => false,
    };
    Ok(match kind {
        "s3" => {
            if t.map.contains_key("access_key_id_secret")
                || t.map.contains_key("secret_access_key_secret")
            {
                return Err(err!(
                    "{}: `*_secret` keys read the sink's credentials from the vault, which any client can also read. \
                     Put the credentials in files (mode 0600) and use access_key_id_file / secret_access_key_file \
                     (or *_credential for systemd credentials) instead",
                    t.what
                ));
            }
            let endpoint = t.url("endpoint", None, insecure)?;
            let region = t.str("region")?.unwrap_or_else(|| "us-east-1".into());
            let prefix = t.str("prefix")?.unwrap_or_else(|| "bouncer".into());
            SinkKind::S3(S3Config {
                endpoint,
                bucket: t.req("bucket")?,
                region,
                prefix: prefix.trim_matches('/').to_string(),
                path_style: t.bool("path_style", true)?,
                access_key_id: t.req_secret("access_key_id")?,
                secret_access_key: t.req_secret("secret_access_key")?,
                conditional_put: t.bool("conditional_put", true)?,
            })
        }
        "file" => SinkKind::File {
            path: t.req("path")?.into(),
        },
        "influxdb" => {
            let measurement = t
                .str("measurement")?
                .unwrap_or_else(|| "bouncer_audit".into());
            // InfluxDB reserves names starting with `_`; control characters cannot be sent.
            if measurement.is_empty()
                || measurement.starts_with('_')
                || measurement.chars().any(char::is_control)
            {
                return Err(err!(
                    "{}: measurement must be non-empty, printable and not start with `_`",
                    t.what
                ));
            }
            SinkKind::Influx(InfluxConfig {
                endpoint: t.url("endpoint", None, insecure)?,
                org: t.req("org")?,
                bucket: t.req("bucket")?,
                token: t.req_secret("token")?,
                measurement,
            })
        }
        "http" => SinkKind::Http(HttpConfig {
            url: t.url("url", None, insecure)?,
            hmac_secret: t.secret("hmac_secret")?,
        }),
        "syslog" => {
            let fac = t.str("facility")?.unwrap_or_else(|| "authpriv".into());
            SinkKind::Syslog(SyslogConfig {
                socket: t
                    .str("socket")?
                    .map(PathBuf::from)
                    .unwrap_or_else(default_syslog_socket),
                facility: facility(&fac)
                    .ok_or_else(|| err!("{}: unknown syslog facility `{fac}`", t.what))?,
            })
        }
        other => {
            return Err(err!(
                "{}: unknown sink type `{other}` (use s3, file, influxdb, http or syslog)",
                t.what
            ));
        }
    })
}

/// Every key is read and checked whether or not the check is enabled, and unknown keys are
/// errors, so a typo such as `enabeld = true` cannot silently leave it off.
fn parse_admission(mut t: Tbl) -> Result<Option<AdmissionConfig>> {
    let enabled = t.bool("enabled", false)?;
    let insecure = t.bool("allow_insecure_http", false)?;
    let provider = match t.str("provider")?.as_deref() {
        Some("anthropic") | None => Provider::Anthropic,
        Some("openai") => Provider::OpenAi,
        Some(p) => {
            return Err(err!(
                "[admission]: unknown provider `{p}` (anthropic or openai)"
            ));
        }
    };
    let default_endpoint = match provider {
        Provider::Anthropic => "https://api.anthropic.com/v1/messages",
        Provider::OpenAi => "https://api.openai.com/v1/chat/completions",
    };
    let on_error_allow = match t.str("on_error")?.as_deref() {
        Some("deny") | None => false,
        Some("allow") => true,
        Some(o) => {
            return Err(err!(
                "[admission]: on_error must be \"deny\" or \"allow\", not `{o}`"
            ));
        }
    };
    let endpoint = t.url("endpoint", Some(default_endpoint), insecure)?;
    let model = t.str("model")?;
    let api_key = t.secret("api_key")?;
    let timeout = Duration::from_millis(t.int("timeout_ms", 8000)?.clamp(100, 120_000));
    let system_prompt_file = t.str("system_prompt_file")?.map(PathBuf::from);
    let cache_ttl = Duration::from_secs(t.int("cache_ttl_secs", 0)?);
    let history = t.int("history", 5)?.min(50) as usize;
    let what = t.what.clone();
    t.done()?;
    if !enabled {
        return Ok(None);
    }
    let required = |k: &str| err!("{what}: `{k}` is required when enabled = true");
    Ok(Some(AdmissionConfig {
        provider,
        endpoint,
        model: model.ok_or_else(|| required("model"))?,
        api_key: api_key.ok_or_else(|| required("api_key_file or api_key_credential"))?,
        timeout,
        on_error_allow,
        system_prompt_file,
        cache_ttl,
        history,
    }))
}

/// Looks up a user name or numeric uid.
pub fn lookup_user(name: &str) -> Result<(u32, u32)> {
    let c = std::ffi::CString::new(name).map_err(|_| err!("bad user name"))?;
    // SAFETY: getpwnam returns NULL or a pointer to static storage; read immediately.
    unsafe {
        let pw = libc::getpwnam(c.as_ptr());
        if !pw.is_null() {
            return Ok(((*pw).pw_uid, (*pw).pw_gid));
        }
        if let Ok(uid) = name.parse::<u32>() {
            let pw = libc::getpwuid(uid);
            if !pw.is_null() {
                return Ok(((*pw).pw_uid, (*pw).pw_gid));
            }
        }
    }
    Err(err!("unknown user `{name}`"))
}

/// Looks up a group name or numeric gid.
pub fn lookup_group(name: &str) -> Result<u32> {
    if let Ok(gid) = name.parse::<u32>() {
        return Ok(gid);
    }
    let c = std::ffi::CString::new(name).map_err(|_| err!("bad group name"))?;
    // SAFETY: getgrnam returns NULL or a pointer to static storage; read immediately.
    unsafe {
        let gr = libc::getgrnam(c.as_ptr());
        if gr.is_null() {
            return Err(err!("unknown group `{name}`"));
        }
        Ok((*gr).gr_gid)
    }
}

impl Config {
    /// Loads config: defaults, then the config file (if present), then env overrides.
    pub fn load(config_flag: Option<PathBuf>, socket_flag: Option<PathBuf>) -> Result<Config> {
        let d = defaults();
        let config_file = config_flag
            .or_else(|| env::var_os("BOUNCER_CONFIG").map(PathBuf::from))
            .unwrap_or_else(|| d.config_dir.join("config.toml"));
        let me = util::geteuid();
        let mut c = Config {
            config_file: config_file.clone(),
            socket: d.socket,
            socket_mode: 0o660,
            socket_group: None,
            admin_socket: None,
            server_uid: me,
            user: None,
            vault: d.data_dir.join("vault.bin"),
            key: KeySource::File(d.config_dir.join("key")),
            audit_log: d.data_dir.join("audit.jsonl"),
            audit_fsync: FsyncMode::Async,
            context_vars: DEFAULT_CONTEXT_VARS.iter().map(|s| s.to_string()).collect(),
            min_reason_len: 8,
            require_write_reason: false,
            max_chain_depth: 16,
            require_attribution: true,
            allowed_uids: vec![me],
            admin_uids: vec![me],
            max_connections: 64,
            request_timeout: Duration::from_secs(5),
            mlock: true,
            deny_debugger: false,
            sinks: Vec::new(),
            admission: None,
            uid_defaults: (true, true, true),
        };
        match std::fs::read_to_string(&config_file) {
            Ok(src) => c
                .apply(parse_toml(&src)?)
                .map_err(|e| err!("{}: {e}", config_file.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(err!("cannot read {}: {e}", config_file.display())),
        }
        if let Some(s) = socket_flag.or_else(|| env::var_os("BOUNCER_SOCKET").map(PathBuf::from)) {
            c.socket = s;
        }
        if let Ok(u) = env::var("BOUNCER_SERVER_UID") {
            c.server_uid = u
                .parse()
                .map_err(|_| err!("BOUNCER_SERVER_UID must be a number"))?;
        }
        Ok(c)
    }

    pub fn apply(&mut self, mut doc: Doc) -> Result<()> {
        let mut t = Tbl::new("", std::mem::take(&mut doc.root));
        if let Some(v) = t.str("socket")? {
            self.socket = v.into();
        }
        if let Some(v) = t.str("socket_mode")? {
            self.socket_mode = parse_mode(&v, "socket_mode")?;
        }
        self.socket_group = t.str("socket_group")?;
        self.admin_socket = t.str("admin_socket")?.map(PathBuf::from);
        let server_uid = t.int("server_uid", u64::MAX)?;
        if server_uid != u64::MAX {
            self.uid_defaults.2 = false;
            self.server_uid =
                u32::try_from(server_uid).map_err(|_| err!("server_uid is too large"))?;
        }
        self.user = t.str("user")?;
        if let Some(v) = t.str("vault")? {
            self.vault = v.into();
        }
        if let Some(v) = t.str("audit_log")? {
            self.audit_log = v.into();
        }
        let key_file = t.str("key")?;
        let key_cred = t.str("key_credential")?;
        let key_cmd = t.list("key_command")?;
        self.key = match (key_file, key_cred, key_cmd) {
            (None, None, None) => self.key.clone(),
            (Some(f), None, None) => KeySource::File(f.into()),
            (None, Some(c), None) if !c.is_empty() && !c.contains('/') => KeySource::Credential(c),
            (None, Some(_), None) => return Err(err!("key_credential must be a plain name")),
            (None, None, Some(cmd)) if !cmd.is_empty() => KeySource::Command(cmd),
            (None, None, Some(_)) => return Err(err!("key_command must not be empty")),
            _ => return Err(err!("set only one of key, key_credential and key_command")),
        };
        if let Some(v) = t.list("context_vars")? {
            if v.len() > 16 {
                return Err(err!("context_vars takes at most 16 names"));
            }
            self.context_vars = v;
        }
        self.min_reason_len = t
            .int("min_reason_len", self.min_reason_len as u64)?
            .min(1000) as usize;
        self.require_write_reason = t.bool("require_write_reason", self.require_write_reason)?;
        self.max_chain_depth = t
            .int("max_chain_depth", self.max_chain_depth as u64)?
            .clamp(1, 64) as usize;
        self.require_attribution = t.bool("require_attribution", self.require_attribution)?;
        if let Some(v) = t.uids("allowed_uids")? {
            self.allowed_uids = v;
            self.uid_defaults.0 = false;
        }
        if let Some(v) = t.uids("admin_uids")? {
            self.admin_uids = v;
            self.uid_defaults.1 = false;
        }
        self.max_connections = t
            .int("max_connections", self.max_connections as u64)?
            .clamp(1, 4096) as usize;
        self.request_timeout = Duration::from_millis(
            t.int(
                "request_timeout_ms",
                self.request_timeout.as_millis() as u64,
            )?
            .clamp(100, 600_000),
        );
        self.mlock = t.bool("mlock", self.mlock)?;
        self.deny_debugger = t.bool("deny_debugger", self.deny_debugger)?;
        if let Some(v) = t.str("audit_fsync")? {
            self.audit_fsync = match v.as_str() {
                "async" => FsyncMode::Async,
                "strict" => FsyncMode::Strict,
                _ => return Err(err!("audit_fsync must be \"async\" or \"strict\"")),
            };
        }
        t.done()?;

        // Legacy single [s3] table.
        if let Some(map) = doc.tables.remove("s3") {
            let mut t = Tbl::new("[s3]", map);
            let kind = parse_sink(&mut t, "s3")?;
            t.done()?;
            self.sinks.push(SinkConfig {
                name: "s3".into(),
                kind,
            });
        }
        for (i, map) in doc
            .arrays
            .remove("sink")
            .unwrap_or_default()
            .into_iter()
            .enumerate()
        {
            let mut t = Tbl::new(format!("[[sink]] #{}", i + 1), map);
            let kind_name = t.req("type")?;
            let name = t.str("name")?;
            let kind = parse_sink(&mut t, &kind_name)?;
            t.done()?;
            let name = name.unwrap_or_else(|| {
                if self
                    .sinks
                    .iter()
                    .any(|s| s.kind.type_name() == kind.type_name())
                {
                    format!("{}-{}", kind.type_name(), i + 1)
                } else {
                    kind.type_name().to_string()
                }
            });
            if name.is_empty()
                || name.len() > 64
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            {
                return Err(err!("sink name `{name}` must be 1-64 of A-Z a-z 0-9 - _"));
            }
            if self.sinks.iter().any(|s| s.name == name) {
                return Err(err!(
                    "two sinks are named `{name}`; give them distinct `name`s"
                ));
            }
            self.sinks.push(SinkConfig { name, kind });
        }
        if let Some(map) = doc.tables.remove("admission") {
            self.admission = parse_admission(Tbl::new("[admission]", map))?;
        }
        let mut extra: Vec<String> = doc.tables.keys().map(|k| format!("[{k}]")).collect();
        extra.extend(doc.arrays.keys().map(|k| format!("[[{k}]]")));
        if !extra.is_empty() {
            return Err(err!("unknown config table(s): {}", extra.join(", ")));
        }
        Ok(())
    }

    /// After dropping privileges to `uid`, defaulted uid lists follow the new uid.
    pub fn rebase_uid_defaults(&mut self, uid: u32) {
        if self.uid_defaults.0 {
            self.allowed_uids = vec![uid];
        }
        if self.uid_defaults.1 {
            self.admin_uids = vec![uid];
        }
        if self.uid_defaults.2 {
            self.server_uid = uid;
        }
    }

    /// Every credential the config refers to (sinks, admission).
    pub fn secret_refs(&self) -> Vec<&SecretRef> {
        let mut v = Vec::new();
        for s in &self.sinks {
            match &s.kind {
                SinkKind::S3(c) => v.extend([&c.access_key_id, &c.secret_access_key]),
                SinkKind::Influx(c) => v.push(&c.token),
                SinkKind::Http(c) => v.extend(c.hmac_secret.as_ref()),
                SinkKind::File { .. } | SinkKind::Syslog(_) => {}
            }
        }
        if let Some(a) = &self.admission {
            v.push(&a.api_key);
        }
        v
    }

    /// Cursor file for a sink, next to the audit log.
    pub fn sink_cursor(&self, sink: &str) -> PathBuf {
        let mut p = self.audit_log.clone().into_os_string();
        p.push(format!(".{sink}.cursor"));
        PathBuf::from(p)
    }

    /// The lock file guarding the store (next to the vault).
    pub fn lock_path(&self) -> PathBuf {
        let (dir, _) = util::split_path(&self.vault).unwrap_or((".".into(), "".as_ref()));
        dir.join("bouncer.lock")
    }

    /// Uids that may connect to the main socket.
    pub fn may_connect(&self, uid: u32) -> bool {
        self.allowed_uids.contains(&uid) || self.admin_uids.contains(&uid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blank() -> Config {
        Config::load(Some("/nonexistent/x".into()), None).unwrap()
    }

    #[test]
    fn parses_subset() {
        let src = r#"
# comment
socket = "/run/b.sock" # trailing
socket_mode = "0660"
min_reason_len = 12
context_vars = ["A", "B#C", "D\"E"]
allowed_uids = [1000, 1001]
audit_fsync = "strict"
key_command = ["security", "find-generic-password", "-w"]

[[sink]]
type = "s3"
endpoint = "https://s3.example.com/"
bucket = "audit"
path_style = false
access_key_id_file = "/etc/bouncer/ak"
secret_access_key_credential = "s3-secret"

[[sink]]
type = "file"
path = "/mnt/backup/audit.jsonl"

[[sink]]
type = "syslog"
facility = "local3"

[admission]
enabled = true
provider = "openai"
model = "some-model"
api_key_file = "/etc/bouncer/llm.key"
"#;
        let doc = parse_toml(src).unwrap();
        assert_eq!(doc.root["socket"], Value::Str("/run/b.sock".into()));
        assert_eq!(
            doc.root["context_vars"],
            Value::List(vec!["A".into(), "B#C".into(), "D\"E".into()])
        );
        assert_eq!(doc.arrays["sink"].len(), 3);
        let mut c = blank();
        c.apply(doc).unwrap();
        assert_eq!(c.min_reason_len, 12);
        assert_eq!(c.allowed_uids, vec![1000, 1001]);
        assert_eq!(c.audit_fsync, FsyncMode::Strict);
        assert!(matches!(c.key, KeySource::Command(ref v) if v.len() == 3));
        let names: Vec<_> = c.sinks.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["s3", "file", "syslog"]);
        let SinkKind::S3(s3) = &c.sinks[0].kind else {
            panic!()
        };
        assert_eq!(s3.endpoint, "https://s3.example.com");
        assert_eq!(
            s3.secret_access_key,
            SecretRef::Credential("s3-secret".into())
        );
        assert!(s3.conditional_put);
        let SinkKind::Syslog(sl) = &c.sinks[2].kind else {
            panic!()
        };
        assert_eq!(sl.facility, 19);
        let a = c.admission.unwrap();
        assert_eq!(a.provider, Provider::OpenAi);
        assert!(a.endpoint.ends_with("/chat/completions"));
        assert!(!a.on_error_allow);
        assert_eq!(a.timeout, Duration::from_millis(8000));
    }

    #[test]
    fn rejects_unknown_and_bad() {
        let bad = |src: &str| {
            let mut c = blank();
            parse_toml(src)
                .and_then(|d| c.apply(d))
                .err()
                .map(|e| e.to_string())
        };
        assert!(bad("sockett = \"x\"").unwrap().contains("sockett"));
        assert!(parse_toml("x = \"unterminated").is_err());
        assert!(parse_toml("just words").is_err());
        assert!(parse_toml("a = 1\na = 2").is_err());
        assert!(bad("[[sink]]\ntype = \"ftp\"").unwrap().contains("ftp"));
        assert!(
            bad("[[sink]]\ntype = \"file\"\npath = \"/x\"\nbogus = 1")
                .unwrap()
                .contains("bogus")
        );
        // https is required unless explicitly relaxed.
        let e = bad("[[sink]]\ntype = \"http\"\nurl = \"http://example.com/hook\"").unwrap();
        assert!(e.contains("https"), "{e}");
        assert!(
            bad("[[sink]]\ntype = \"http\"\nurl = \"http://x/h\"\nallow_insecure_http = true")
                .is_none()
        );
        // Legacy vault-held S3 credentials get a migration message.
        let e = bad("[s3]\nendpoint = \"https://s3\"\nbucket = \"b\"\naccess_key_id_secret = \"A\"\nsecret_access_key_secret = \"B\"").unwrap();
        assert!(e.contains("access_key_id_file"), "{e}");
        assert!(bad("key = \"/k\"\nkey_credential = \"k\"").is_some());
        assert!(bad("socket_mode = \"0066\"").is_some());
        assert!(
            bad("[admission]\nenabled = true\nmodel = \"m\"")
                .unwrap()
                .contains("api_key")
        );
        assert!(bad("[admission]\nenabled = false\nmodel = \"m\"").is_none());
        // A misspelt or mistyped key is an error even when the check is (or looks) off.
        let e = bad("[admission]\nenabeld = true\nmodel = \"m\"\napi_key_file = \"/k\"").unwrap();
        assert!(e.contains("enabeld"), "{e}");
        assert!(bad("[admission]\nenabled = false\nmodle = \"m\"").is_some());
        assert!(bad("[admission]\nenabled = \"true\"").is_some());
        assert!(bad("[admission]\nenabled = false\ntimeout_ms = \"5s\"").is_some());
        assert!(bad("[admission]\nenabled = false\nprovider = \"opneai\"").is_some());
        assert!(bad("[admission]\nendpoint = \"http://x\"").is_some());
        assert!(bad("[admission]\n").is_none());
        let influx = "[[sink]]\ntype = \"influxdb\"\nendpoint = \"https://i\"\norg = \"o\"\nbucket = \"b\"\ntoken_file = \"/t\"\n";
        assert!(bad(&format!("{influx}measurement = \"_bad\"")).is_some());
        assert!(bad(&format!("{influx}measurement = \"\"")).is_some());
        assert!(bad(&format!("{influx}measurement = \"ok name\"")).is_none());
        let e =
            bad("[[sink]]\ntype = \"file\"\npath = \"/x\"\nallow_insecure_http = true").unwrap();
        assert!(e.contains("allow_insecure_http"), "{e}");
        assert!(bad("[[sink]]\ntype = \"file\"\npath = \"/a\"\nname = \"x\"\n[[sink]]\ntype = \"file\"\npath = \"/b\"\nname = \"x\"").is_some());
    }
}
