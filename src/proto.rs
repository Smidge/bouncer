//! Wire protocol: one JSON request line, one JSON response line, per Unix socket connection.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::err;
use crate::util::Result;

/// Largest request line for anything but `set`.
pub const MAX_FRAME: usize = 64 * 1024;
/// Largest `set` request line (a value of `MAX_VALUE` bytes, JSON-escaped, fits).
pub const MAX_SET_FRAME: usize = 2 * 1024 * 1024;
/// Largest secret value.
pub const MAX_VALUE: usize = 256 * 1024;
/// Largest response line (e.g. `exec` with several values).
pub const MAX_RESPONSE: usize = 4 * 1024 * 1024;
/// Secret names per request. With names of at most 128 characters this keeps every
/// request's audit entry well under `audit::MAX_ENTRY` (see the audit tests).
pub const MAX_NAMES: usize = 64;
/// Longest reason, in characters. Longer requests are rejected, not cut.
pub const MAX_REASON: usize = 1000;
/// Longest description, in characters. Longer requests are rejected, not cut.
pub const MAX_DESC: usize = 500;
/// Tags per secret.
pub const MAX_TAGS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    Get,
    Exec,
    Set,
    Rm,
    Ls,
    Status,
    Verify,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Get => "get",
            Op::Exec => "exec",
            Op::Set => "set",
            Op::Rm => "rm",
            Op::Ls => "ls",
            Op::Status => "status",
            Op::Verify => "verify",
        }
    }

    /// Releases secret values to the caller.
    pub fn is_read(self) -> bool {
        matches!(self, Op::Get | Op::Exec)
    }

    pub fn is_write(self) -> bool {
        matches!(self, Op::Set | Op::Rm)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub op: Op,
    #[serde(default)]
    pub names: Vec<String>,
    #[serde(default)]
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<SecretValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// `verify`: an anchored head, `SEQ:HASH`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect_head: Option<String>,
}

/// A secret value in transit: wiped on drop, never printed by `Debug`.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretValue(pub String);

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[secret]")
    }
}

impl Request {
    pub fn new(op: Op, names: Vec<String>, reason: String) -> Request {
        Request {
            op,
            names,
            reason,
            value: None,
            desc: None,
            tags: Vec::new(),
            expect_head: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListItem {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    pub updated: String,
}

/// Error codes, mapped to exit codes by the CLI.
pub const E_BAD_REQUEST: &str = "bad_request";
pub const E_DENIED: &str = "denied";
pub const E_NOT_FOUND: &str = "not_found";
pub const E_INTERNAL: &str = "internal";
pub const E_AUDIT: &str = "audit_failed";
pub const E_BUSY: &str = "busy";
pub const E_VERIFY: &str = "verify_failed";

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<SecretValue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub list: Vec<ListItem>,
    /// The admission model's reasoning, when it was consulted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<serde_json::Value>,
}

impl Response {
    pub fn fail(code: &str, error: impl Into<String>) -> Response {
        Response {
            ok: false,
            code: Some(code.into()),
            error: Some(error.into()),
            ..Default::default()
        }
    }

    /// Serialises to one line; the buffer is wiped on drop.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut line =
            Zeroizing::new(serde_json::to_vec(self).unwrap_or_else(|_| b"{\"ok\":false}".to_vec()));
        line.push(b'\n');
        line
    }
}

#[derive(Debug)]
pub enum FrameError {
    TooLarge(usize),
    /// The peer closed the connection before a newline.
    Unterminated,
    Timeout,
    Io(io::Error),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::TooLarge(n) => write!(f, "request is larger than {n} bytes"),
            FrameError::Unterminated => f.write_str("request is not newline-terminated"),
            FrameError::Timeout => f.write_str("request was not received in time"),
            FrameError::Io(e) => write!(f, "{e}"),
        }
    }
}

/// Reads one newline-terminated line before `deadline` (a deadline for the whole line, not
/// per read). Lines starting with `{"op":"set"` may be up to `large`, others up to `small`.
pub fn read_frame(
    stream: &UnixStream,
    deadline: Instant,
    small: usize,
    large: usize,
) -> std::result::Result<Zeroizing<Vec<u8>>, FrameError> {
    let mut buf = Zeroizing::new(Vec::with_capacity(512));
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(FrameError::Timeout);
        }
        stream
            .set_read_timeout(Some(left))
            .map_err(FrameError::Io)?;
        match (&*stream).read(&mut chunk[..]) {
            Ok(0) => return Err(FrameError::Unterminated),
            Ok(n) => {
                let nl = chunk[..n].iter().position(|&b| b == b'\n');
                buf.extend_from_slice(&chunk[..nl.unwrap_or(n)]);
                let limit = if buf.starts_with(b"{\"op\":\"set\"") {
                    large
                } else {
                    small
                };
                if buf.len() > limit {
                    return Err(FrameError::TooLarge(limit));
                }
                if nl.is_some() {
                    return Ok(buf);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(FrameError::Timeout);
            }
            Err(e) => return Err(FrameError::Io(e)),
        }
    }
}

#[derive(Debug)]
pub enum CallError {
    /// Could not connect or talk to the daemon.
    Unreachable(String),
    /// Something is listening, but not as the expected uid.
    Identity(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Unreachable(m) | CallError::Identity(m) => f.write_str(m),
        }
    }
}

/// Sends one request to the daemon and returns its response. Before sending anything the
/// client checks that the socket's owner process runs as `server_uid`, so a socket planted
/// by another user never sees a request (or a `set` value).
pub fn call(
    socket: &Path,
    server_uid: u32,
    req: &Request,
    timeout: Duration,
) -> std::result::Result<Response, CallError> {
    let stream = UnixStream::connect(socket).map_err(|e| {
        CallError::Unreachable(format!(
            "cannot connect to the bouncer daemon at {} ({e}). Is `bouncer serve` running?",
            socket.display()
        ))
    })?;
    let peer = crate::peer::peer_cred(&stream).map_err(|e| {
        CallError::Identity(format!("cannot check who owns {}: {e}", socket.display()))
    })?;
    if peer.uid != server_uid {
        return Err(CallError::Identity(format!(
            "the process listening on {} runs as uid {}, not the expected uid {server_uid}; refusing to talk to it \
             (set server_uid in the config or BOUNCER_SERVER_UID if the daemon runs as another user)",
            socket.display(),
            peer.uid
        )));
    }
    let io = |e: io::Error| CallError::Unreachable(format!("talking to the daemon: {e}"));
    stream.set_write_timeout(Some(timeout)).map_err(io)?;
    let mut line = Zeroizing::new(
        serde_json::to_vec(req)
            .map_err(|_| CallError::Unreachable("cannot encode request".into()))?,
    );
    line.push(b'\n');
    (&stream).write_all(&line).map_err(io)?;
    let resp = match read_frame(
        &stream,
        Instant::now() + timeout,
        MAX_RESPONSE,
        MAX_RESPONSE,
    ) {
        Ok(r) => r,
        Err(FrameError::Unterminated) => {
            return Err(CallError::Unreachable(
                "daemon closed the connection without answering".into(),
            ));
        }
        Err(e) => {
            return Err(CallError::Unreachable(format!(
                "reading the daemon's answer: {e}"
            )));
        }
    };
    serde_json::from_slice(&resp)
        .map_err(|_| CallError::Unreachable("malformed response from daemon".into()))
}

/// Convenience for internal callers that want a plain error.
pub fn call_simple(socket: &Path, server_uid: u32, req: &Request) -> Result<Response> {
    call(socket, server_uid, req, Duration::from_secs(60)).map_err(|e| err!("{e}"))
}
