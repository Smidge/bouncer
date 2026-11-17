//! Wire protocol: one JSON request line, one JSON response line, per Unix socket connection.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::err;
use crate::util::Result;

/// Largest request or response line accepted.
pub const MAX_LINE: u64 = 4 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    Get,
    Exec,
    Set,
    Rm,
    Ls,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Get => "get",
            Op::Exec => "exec",
            Op::Set => "set",
            Op::Rm => "rm",
            Op::Ls => "ls",
        }
    }

    /// Reads release secret values to the caller.
    pub fn is_read(self) -> bool {
        matches!(self, Op::Get | Op::Exec)
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
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
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

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub list: Vec<ListItem>,
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
}

/// Reads one newline-terminated line, capped at `MAX_LINE` bytes.
pub fn read_line(stream: &UnixStream) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    BufReader::new(stream.take(MAX_LINE)).read_until(b'\n', &mut buf)?;
    Ok(buf)
}

/// Sends one request to the daemon and returns its response.
pub fn call(socket: &Path, req: &Request) -> Result<Response> {
    let mut stream = UnixStream::connect(socket).map_err(|e| {
        err!(
            "cannot connect to the bouncer daemon at {} ({e}). Is `bouncer serve` running?",
            socket.display()
        )
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    let mut line = serde_json::to_vec(req).map_err(|_| err!("cannot encode request"))?;
    line.push(b'\n');
    stream.write_all(&line)?;
    let resp = read_line(&stream)?;
    if resp.is_empty() {
        return Err(err!("daemon closed the connection without answering"));
    }
    serde_json::from_slice(&resp).map_err(|_| err!("malformed response from daemon"))
}
