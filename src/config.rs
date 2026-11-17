//! Configuration: default paths plus a small config file.
//!
//! The file format is a strict subset of TOML (top-level keys, one `[s3]` table, string,
//! integer, boolean and single-line string-array values, `#` comments). Parsing that subset
//! takes ~80 lines, while the `toml` crate would add several dependencies for no gain here.

use std::collections::HashMap;
use std::env;
use std::path::{Path, PathBuf};

use crate::err;
use crate::util::{Error, Result};

pub const DEFAULT_CONTEXT_VARS: &[&str] = &[
    "T3CODE_THREAD_ID",
    "CLAUDE_CODE_SESSION_ID",
    "CODEX_THREAD_ID",
    "CODEX_SESSION_ID",
];

#[derive(Clone, Debug, PartialEq)]
pub enum FsyncMode {
    /// A background thread fsyncs the audit log right after each append (default).
    Async,
    /// Fsync the audit log before releasing a secret.
    Strict,
}

#[derive(Clone, Debug)]
pub struct S3Config {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub prefix: String,
    pub path_style: bool,
    /// Names of the vault secrets that hold the sink's own credentials.
    pub access_key_id_secret: String,
    pub secret_access_key_secret: String,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub config_file: PathBuf,
    pub socket: PathBuf,
    pub socket_mode: u32,
    pub vault: PathBuf,
    pub key: PathBuf,
    pub audit_log: PathBuf,
    pub context_vars: Vec<String>,
    pub min_reason_len: usize,
    pub max_chain_depth: usize,
    pub allowed_uids: Vec<u32>,
    pub audit_fsync: FsyncMode,
    pub s3: Option<S3Config>,
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
    let runtime = match env::var_os("XDG_RUNTIME_DIR") {
        Some(r) if Path::new(&r).is_absolute() => PathBuf::from(r).join("bouncer"),
        _ => PathBuf::from(format!("/tmp/bouncer-{}", crate::util::getuid())),
    };
    Defaults {
        config_dir: xdg("XDG_CONFIG_HOME", ".config").join("bouncer"),
        data_dir: xdg("XDG_DATA_HOME", ".local/share").join("bouncer"),
        socket: runtime.join("bouncer.sock"),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    List(Vec<String>),
}

/// Parses the TOML subset into `section.key -> value` (top-level keys have no prefix).
pub fn parse_toml(src: &str) -> Result<HashMap<String, Value>> {
    let mut out = HashMap::new();
    let mut section = String::new();
    for (i, raw) in src.lines().enumerate() {
        let lineno = i + 1;
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let name = rest
                .strip_suffix(']')
                .ok_or_else(|| err!("config line {lineno}: bad table header"))?;
            section = format!("{}.", name.trim());
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| err!("config line {lineno}: expected key = value"))?;
        let value = parse_value(v.trim()).map_err(|e| err!("config line {lineno}: {e}"))?;
        out.insert(format!("{section}{}", k.trim()), value);
    }
    Ok(out)
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

impl Config {
    /// Loads config: defaults, then the config file (if present), then env overrides.
    pub fn load(config_flag: Option<PathBuf>, socket_flag: Option<PathBuf>) -> Result<Config> {
        let d = defaults();
        let config_file = config_flag
            .or_else(|| env::var_os("BOUNCER_CONFIG").map(PathBuf::from))
            .unwrap_or_else(|| d.config_dir.join("config.toml"));
        let mut c = Config {
            config_file: config_file.clone(),
            socket: d.socket,
            socket_mode: 0o600,
            vault: d.data_dir.join("vault.bin"),
            key: d.config_dir.join("key"),
            audit_log: d.data_dir.join("audit.jsonl"),
            context_vars: DEFAULT_CONTEXT_VARS.iter().map(|s| s.to_string()).collect(),
            min_reason_len: 8,
            max_chain_depth: 16,
            allowed_uids: vec![crate::util::getuid()],
            audit_fsync: FsyncMode::Async,
            s3: None,
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
        Ok(c)
    }

    fn apply(&mut self, mut map: HashMap<String, Value>) -> Result<()> {
        let mut take = |k: &str| map.remove(k);
        if let Some(v) = take("socket") {
            self.socket = path(v, "socket")?;
        }
        if let Some(v) = take("socket_mode") {
            let s = string(v, "socket_mode")?;
            self.socket_mode =
                u32::from_str_radix(&s, 8).map_err(|_| err!("socket_mode must be octal"))?;
        }
        if let Some(v) = take("vault") {
            self.vault = path(v, "vault")?;
        }
        if let Some(v) = take("key") {
            self.key = path(v, "key")?;
        }
        if let Some(v) = take("audit_log") {
            self.audit_log = path(v, "audit_log")?;
        }
        if let Some(v) = take("context_vars") {
            self.context_vars = list(v, "context_vars")?;
        }
        if let Some(v) = take("min_reason_len") {
            self.min_reason_len = int(v, "min_reason_len")? as usize;
        }
        if let Some(v) = take("max_chain_depth") {
            self.max_chain_depth = (int(v, "max_chain_depth")? as usize).clamp(1, 64);
        }
        if let Some(v) = take("allowed_uids") {
            let Value::List(items) = v else {
                return Err(err!("allowed_uids must be a list, e.g. [1000, 1001]"));
            };
            self.allowed_uids = items
                .iter()
                .map(|s| s.parse().map_err(|_| err!("bad uid `{s}` in allowed_uids")))
                .collect::<Result<_>>()?;
        }
        if let Some(v) = take("audit_fsync") {
            self.audit_fsync = match string(v, "audit_fsync")?.as_str() {
                "async" => FsyncMode::Async,
                "strict" => FsyncMode::Strict,
                _ => return Err(err!("audit_fsync must be \"async\" or \"strict\"")),
            };
        }
        if let Some(v) = take("s3.bucket") {
            let mut need = |k: &str| {
                take(&format!("s3.{k}"))
                    .ok_or_else(|| err!("[s3] needs `{k}`"))
                    .and_then(|v| string(v, k))
            };
            let endpoint = need("endpoint")?;
            let access_key_id_secret = need("access_key_id_secret")?;
            let secret_access_key_secret = need("secret_access_key_secret")?;
            let region = match take("s3.region") {
                Some(v) => string(v, "region")?,
                None => "us-east-1".into(),
            };
            let prefix = match take("s3.prefix") {
                Some(v) => string(v, "prefix")?,
                None => "bouncer".into(),
            };
            let path_style = match take("s3.path_style") {
                Some(Value::Bool(b)) => b,
                None => true,
                Some(_) => return Err(err!("path_style must be true or false")),
            };
            self.s3 = Some(S3Config {
                endpoint: endpoint.trim_end_matches('/').to_string(),
                bucket: string(v, "bucket")?,
                region,
                prefix: prefix.trim_matches('/').to_string(),
                path_style,
                access_key_id_secret,
                secret_access_key_secret,
            });
        }
        let mut unknown: Vec<_> = map.keys().cloned().collect();
        if unknown.is_empty() {
            return Ok(());
        }
        unknown.sort();
        Err(err!("unknown config key(s): {}", unknown.join(", ")))
    }

    /// File holding the S3 upload cursor, next to the audit log.
    pub fn s3_cursor(&self) -> PathBuf {
        let mut p = self.audit_log.clone().into_os_string();
        p.push(".s3cursor");
        PathBuf::from(p)
    }
}

fn string(v: Value, k: &str) -> Result<String> {
    match v {
        Value::Str(s) => Ok(s),
        _ => Err(err!("{k} must be a string")),
    }
}

fn path(v: Value, k: &str) -> Result<PathBuf> {
    string(v, k).map(PathBuf::from)
}

fn int(v: Value, k: &str) -> Result<i64> {
    match v {
        Value::Int(i) if i >= 0 => Ok(i),
        _ => Err(err!("{k} must be a non-negative integer")),
    }
}

fn list(v: Value, k: &str) -> Result<Vec<String>> {
    match v {
        Value::List(l) => Ok(l),
        _ => Err(Error(format!("{k} must be a list of strings"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_subset() {
        let src = r#"
# comment
socket = "/run/b.sock" # trailing
min_reason_len = 12
context_vars = ["A", "B#C", "D\"E"]
allowed_uids = [1000, 1001]
audit_fsync = "strict"

[s3]
endpoint = "https://s3.example.com/"
bucket = "audit"
path_style = false
access_key_id_secret = "AK"
secret_access_key_secret = "SK"
"#;
        let map = parse_toml(src).unwrap();
        assert_eq!(map["socket"], Value::Str("/run/b.sock".into()));
        assert_eq!(map["min_reason_len"], Value::Int(12));
        assert_eq!(
            map["context_vars"],
            Value::List(vec!["A".into(), "B#C".into(), "D\"E".into()])
        );
        assert_eq!(map["s3.path_style"], Value::Bool(false));
        let mut c = Config::load(Some("/nonexistent/x".into()), None).unwrap();
        c.apply(map).unwrap();
        assert_eq!(c.min_reason_len, 12);
        assert_eq!(c.allowed_uids, vec![1000, 1001]);
        assert_eq!(c.audit_fsync, FsyncMode::Strict);
        let s3 = c.s3.unwrap();
        assert_eq!(s3.endpoint, "https://s3.example.com");
        assert_eq!(s3.region, "us-east-1");
        assert!(!s3.path_style);
    }

    #[test]
    fn rejects_unknown_and_bad() {
        let mut c = Config::load(Some("/nonexistent/x".into()), None).unwrap();
        assert!(c.apply(parse_toml("sockett = \"x\"").unwrap()).is_err());
        assert!(parse_toml("x = \"unterminated").is_err());
        assert!(parse_toml("just words").is_err());
    }
}
