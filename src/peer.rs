//! Caller attribution from the OS: peer credentials of the socket and the process ancestry.
//!
//! The peer pid/uid come from the kernel (`SO_PEERCRED` on Linux, `getpeereid` and
//! `LOCAL_PEERPID` on macOS). Context variables such as `CLAUDE_CODE_SESSION_ID` are read
//! from the initial environment of every ancestor up to pid 1; the value from the *oldest*
//! ancestor is the primary one, and every other distinct value is recorded with its pid.
//!
//! These variables are advisory. Any process can start a child with whatever environment it
//! likes, and a process that is reparented to init (double fork, detached daemon) has no
//! agent ancestor at all. See "Caller attribution" in the README.

use std::collections::BTreeMap;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::util::cap;

/// A process's environment, one `NAME=value` per item. Other processes' environments can hold
/// secrets, so every copy is wiped when dropped.
pub(crate) type Env = Zeroizing<Vec<Vec<u8>>>;

/// Ancestors walked before giving up (recorded as `chain_truncated`).
pub const HARD_DEPTH: usize = 512;
/// Characters kept from a context variable value.
pub const MAX_CTX_VALUE: usize = 256;
/// Distinct values recorded per context variable.
pub const MAX_CTX_VALUES: usize = 8;
const MAX_EXE: usize = 256;
const MAX_CWD: usize = 512;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainEntry {
    pub pid: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argv: Option<String>,
    /// False when the process environment could not be read.
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub env: bool,
}

fn yes() -> bool {
    true
}

fn is_true(b: &bool) -> bool {
    *b
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CtxOther {
    pub value: String,
    pub pid: i32,
}

/// A context variable: the oldest ancestor's value, plus other values seen below it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct CtxValue {
    pub value: String,
    pub pid: i32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub other: Vec<CtxOther>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Attribution {
    /// "ok", "partial" (some same-uid ancestor's environment was unreadable) or "unavailable".
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub context: BTreeMap<String, CtxValue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<ChainEntry>,
    /// Processes walked, which can exceed the recorded `chain` (`max_chain_depth`).
    #[serde(default)]
    pub ancestors: usize,
    /// The walk stopped at `HARD_DEPTH` before reaching pid 1.
    #[serde(default, skip_serializing_if = "is_false")]
    pub chain_truncated: bool,
}

impl Attribution {
    pub fn unavailable(why: impl Into<String>) -> Attribution {
        Attribution {
            status: "unavailable".into(),
            error: Some(why.into()),
            ..Default::default()
        }
    }

    pub fn is_unavailable(&self) -> bool {
        self.status == "unavailable"
    }

    /// The primary value of the first configured variable present, used as a thread id.
    pub fn thread(&self, vars: &[String]) -> Option<&str> {
        vars.iter()
            .find_map(|v| self.context.get(v))
            .map(|c| c.value.as_str())
    }

    /// Cuts the record down to fit size limits (see `audit::MAX_ENTRY`).
    pub fn shrink(&mut self) {
        self.chain.truncate(4);
        for c in &mut self.chain {
            c.argv = None;
        }
        for c in self.context.values_mut() {
            c.other.clear();
        }
    }
}

pub fn peer_cred(stream: &UnixStream) -> io::Result<PeerCred> {
    sys::peer_cred(stream.as_raw_fd())
}

/// The connecting process, identified right after accept.
pub struct Caller {
    pub cred: PeerCred,
    pidfd: Option<OwnedFd>,
    start: Option<u64>,
}

impl Caller {
    pub fn identify(stream: &UnixStream) -> io::Result<Caller> {
        let cred = peer_cred(stream)?;
        let pidfd = sys::peer_pidfd(stream.as_raw_fd());
        let start = (cred.pid > 0)
            .then(|| sys::basic(cred.pid).map(|b| b.start))
            .flatten();
        Ok(Caller { cred, pidfd, start })
    }

    /// True if the peer pid still names the same, live process: its pidfd (Linux 6.5+) is
    /// alive and its start time is unchanged. A pid cannot be reused while the process lives.
    pub fn still_same(&self) -> bool {
        if let Some(fd) = &self.pidfd
            && !sys::pidfd_alive(fd)
        {
            return false;
        }
        self.start.is_some() && sys::basic(self.cred.pid).map(|b| b.start) == self.start
    }
}

/// Cheap per-process facts used to walk the tree.
pub(crate) struct Basic {
    ppid: i32,
    uid: Option<u32>,
    start: u64,
}

pub struct Attributor {
    vars: Vec<String>,
    depth: usize,
}

impl Attributor {
    pub fn new(vars: Vec<String>, depth: usize) -> Attributor {
        Attributor { vars, depth }
    }

    /// Walks from `pid` up to pid 1 and gathers attribution. Nothing is cached: a process
    /// can exec (same pid and start time, new image) or rewrite its environment block.
    pub fn attribute(&self, pid: i32) -> Attribution {
        if pid <= 0 {
            return Attribution::unavailable(
                "the kernel did not report the caller's pid (another pid namespace?)",
            );
        }
        let mut chain = Vec::new();
        // (var index, value, pid), newest first.
        let mut found: Vec<(usize, String, i32)> = Vec::new();
        let mut unreadable_same_uid = false;
        let mut first_env_ok = None;
        let mut first_uid = None;
        let mut truncated = false;
        let mut walked = 0;
        let mut cur = pid;
        loop {
            if walked == HARD_DEPTH {
                truncated = true;
                break;
            }
            let Some(b) = sys::basic(cur) else { break };
            walked += 1;
            let (args, env) = sys::args_env(cur);
            // An empty environment means it was hidden from us (macOS does this for Apple
            // platform binaries such as /bin/sh and /bin/zsh), so treat it as unreadable.
            let env_ok = env.as_ref().is_some_and(|e| !e.is_empty());
            if walked == 1 {
                first_env_ok = Some(env_ok);
                first_uid = b.uid;
            } else if !env_ok && b.uid.is_some() && b.uid == first_uid {
                unreadable_same_uid = true;
            }
            for entry in env.iter().flat_map(|e| e.iter()) {
                let Some(eq) = entry.iter().position(|&c| c == b'=') else {
                    continue;
                };
                if let Some(i) = self.vars.iter().position(|v| v.as_bytes() == &entry[..eq]) {
                    let v = String::from_utf8_lossy(&entry[eq + 1..]);
                    found.push((i, cap(&v, MAX_CTX_VALUE), cur));
                }
            }
            if chain.len() < self.depth {
                let exe = sys::exe(cur).or_else(|| args.as_ref().and_then(|a| a.first().cloned()));
                chain.push(ChainEntry {
                    pid: cur,
                    uid: b.uid,
                    exe: exe.map(|e| cap(&e, MAX_EXE)),
                    argv: args.as_deref().map(short_argv),
                    env: env_ok,
                });
            }
            if cur == 1 || b.ppid == cur || b.ppid <= 0 {
                break;
            }
            cur = b.ppid;
        }
        let mut context: BTreeMap<String, CtxValue> = BTreeMap::new();
        // Oldest ancestor first.
        for (i, value, pid) in found.into_iter().rev() {
            let var = &self.vars[i];
            match context.get_mut(var) {
                None => {
                    context.insert(
                        var.clone(),
                        CtxValue {
                            value,
                            pid,
                            other: Vec::new(),
                        },
                    );
                }
                Some(c) => {
                    if c.value != value
                        && c.other.len() < MAX_CTX_VALUES - 1
                        && !c.other.iter().any(|o| o.value == value)
                    {
                        c.other.push(CtxOther { value, pid });
                    }
                }
            }
        }
        let status = match first_env_ok {
            None => {
                return Attribution::unavailable(
                    "the caller's process could not be read (it exited?)",
                );
            }
            Some(false) => "unavailable",
            Some(true) if unreadable_same_uid => "partial",
            Some(true) => "ok",
        };
        Attribution {
            status: status.into(),
            error: (status == "unavailable")
                .then(|| "the caller's environment could not be read".to_string()),
            cwd: sys::cwd(pid).map(|c| cap(&c, MAX_CWD)),
            context,
            chain,
            ancestors: walked,
            chain_truncated: truncated,
        }
    }
}

/// A short, bounded rendering of argv for the audit log.
fn short_argv(args: &[String]) -> String {
    const MAX_ARGS: usize = 8;
    const MAX_ARG: usize = 80;
    let mut s = String::new();
    for (i, a) in args.iter().enumerate() {
        if i == MAX_ARGS {
            s.push_str(" ...");
            break;
        }
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&cap(a, MAX_ARG));
    }
    s
}

#[cfg(target_os = "linux")]
mod sys {
    use super::{Basic, Env, PeerCred};
    use std::fs;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::MetadataExt;
    use zeroize::Zeroizing;

    pub fn peer_cred(fd: i32) -> io::Result<PeerCred> {
        // SAFETY: ucred is plain data and len matches its size.
        unsafe {
            let mut cred: libc::ucred = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            let rc = libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            );
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(PeerCred {
                uid: cred.uid,
                gid: cred.gid,
                pid: cred.pid,
            })
        }
    }

    /// `SO_PEERPIDFD` (Linux 6.5+). Its value is 77 on the generic socket ABI used by
    /// x86, ARM and RISC-V; other architectures fall back to start-time checks.
    pub fn peer_pidfd(fd: i32) -> Option<OwnedFd> {
        if !cfg!(any(
            target_arch = "x86_64",
            target_arch = "x86",
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "riscv64"
        )) {
            return None;
        }
        const SO_PEERPIDFD: libc::c_int = 77;
        let mut pidfd: libc::c_int = -1;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: pidfd and len are valid out-pointers of the sizes passed.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_PEERPIDFD,
                (&mut pidfd as *mut libc::c_int).cast(),
                &mut len,
            )
        };
        // SAFETY: on success the kernel returned a new descriptor that we now own.
        (rc == 0 && pidfd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(pidfd) })
    }

    pub fn pidfd_alive(fd: &OwnedFd) -> bool {
        // SAFETY: pidfd_send_signal with signal 0 only checks that the process exists.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                0,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        rc == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
    }

    pub fn basic(pid: i32) -> Option<Basic> {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // Fields after the command name, which is wrapped in parentheses and may contain spaces.
        let rest = &stat[stat.rfind(')')? + 1..];
        let f: Vec<&str> = rest.split_whitespace().collect();
        Some(Basic {
            ppid: f.get(1)?.parse().ok()?,
            start: f.get(19)?.parse().ok()?,
            uid: fs::metadata(format!("/proc/{pid}")).ok().map(|m| m.uid()),
        })
    }

    fn split_nul(data: &[u8]) -> Vec<Vec<u8>> {
        data.split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .map(<[u8]>::to_vec)
            .collect()
    }

    pub fn args_env(pid: i32) -> (Option<Vec<String>>, Option<Env>) {
        let args = fs::read(format!("/proc/{pid}/cmdline")).ok().map(|d| {
            split_nul(&d)
                .iter()
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect()
        });
        let env = fs::read(format!("/proc/{pid}/environ"))
            .ok()
            .map(|d| Zeroizing::new(split_nul(&Zeroizing::new(d))));
        (args, env)
    }

    pub fn exe(pid: i32) -> Option<String> {
        fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }

    pub fn cwd(pid: i32) -> Option<String> {
        fs::read_link(format!("/proc/{pid}/cwd"))
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
    }
}

#[cfg(target_os = "macos")]
mod sys {
    use super::{Basic, Env, PeerCred};
    use std::cell::RefCell;
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::os::fd::OwnedFd;
    use std::sync::OnceLock;

    pub fn peer_cred(fd: i32) -> io::Result<PeerCred> {
        // SAFETY: all out-pointers are valid locals of the sizes passed.
        unsafe {
            let (mut uid, mut gid) = (0, 0);
            if libc::getpeereid(fd, &mut uid, &mut gid) != 0 {
                return Err(io::Error::last_os_error());
            }
            let mut pid: libc::c_int = 0;
            let mut len = size_of::<libc::c_int>() as libc::socklen_t;
            let rc = libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&mut pid as *mut libc::c_int).cast(),
                &mut len,
            );
            if rc != 0 {
                pid = 0;
            }
            Ok(PeerCred { uid, gid, pid })
        }
    }

    pub fn peer_pidfd(_fd: i32) -> Option<OwnedFd> {
        None
    }

    pub fn pidfd_alive(_fd: &OwnedFd) -> bool {
        true
    }

    pub fn basic(pid: i32) -> Option<Basic> {
        // SAFETY: proc_bsdinfo is plain data and the size passed matches it.
        unsafe {
            let mut info: libc::proc_bsdinfo = zeroed();
            let size = size_of::<libc::proc_bsdinfo>() as libc::c_int;
            let n = libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut info as *mut libc::proc_bsdinfo).cast(),
                size,
            );
            if n != size {
                return None;
            }
            Some(Basic {
                ppid: info.pbi_ppid as i32,
                uid: Some(info.pbi_uid),
                start: info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec,
            })
        }
    }

    fn argmax() -> usize {
        static ARGMAX: OnceLock<usize> = OnceLock::new();
        *ARGMAX.get_or_init(|| {
            let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
            let mut val: libc::c_int = 0;
            let mut len = size_of::<libc::c_int>();
            // SAFETY: mib and the out-pointer are valid for the lengths passed.
            let rc = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    2,
                    (&mut val as *mut libc::c_int).cast(),
                    &mut len,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if rc == 0 && val > 0 {
                val as usize
            } else {
                1 << 20
            }
        })
    }

    thread_local! {
        /// Reused across calls so each lookup does not fault in a fresh ARG_MAX buffer.
        static BUF: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    }

    /// argv and environment via `sysctl(KERN_PROCARGS2)`; only works for same-uid processes
    /// (or as root).
    pub fn args_env(pid: i32) -> (Option<Vec<String>>, Option<Env>) {
        BUF.with_borrow_mut(|buf| {
            if buf.len() < argmax() {
                buf.resize(argmax(), 0);
            }
            let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
            let mut size = buf.len();
            // SAFETY: buf is valid for `size` bytes; the kernel writes at most that much.
            let rc = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    3,
                    buf.as_mut_ptr().cast(),
                    &mut size,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if rc != 0 || size < 4 {
                return (None, None);
            }
            let r = parse_procargs(&buf[..size])
                .map(|(a, e)| (Some(a), Some(zeroize::Zeroizing::new(e))))
                .unwrap_or((None, None));
            zeroize::Zeroize::zeroize(&mut buf[..size]);
            r
        })
    }

    /// Layout: argc (i32), exec path, NUL padding, argv[argc], env..., empty string.
    pub(super) fn parse_procargs(buf: &[u8]) -> Option<(Vec<String>, Vec<Vec<u8>>)> {
        let argc = i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?).max(0) as usize;
        let rest = &buf[4..];
        let rest = &rest[rest.iter().position(|&b| b == 0)?..];
        let rest = &rest[rest.iter().position(|&b| b != 0).unwrap_or(rest.len())..];
        let mut parts = rest.split(|&b| b == 0);
        let argv = parts
            .by_ref()
            .take(argc)
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        let env = parts
            .take_while(|s| !s.is_empty())
            .map(<[u8]>::to_vec)
            .collect();
        Some((argv, env))
    }

    pub fn exe(pid: i32) -> Option<String> {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: buf is valid for the size passed.
        let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
        if n <= 0 {
            return None;
        }
        buf.truncate(n as usize);
        Some(String::from_utf8_lossy(&buf).into_owned())
    }

    pub fn cwd(pid: i32) -> Option<String> {
        // SAFETY: proc_vnodepathinfo is plain data and the size passed matches it.
        unsafe {
            let mut info: libc::proc_vnodepathinfo = zeroed();
            let size = size_of::<libc::proc_vnodepathinfo>() as libc::c_int;
            let n = libc::proc_pidinfo(
                pid,
                libc::PROC_PIDVNODEPATHINFO,
                0,
                (&mut info as *mut libc::proc_vnodepathinfo).cast(),
                size,
            );
            if n != size {
                return None;
            }
            let path = &info.pvi_cdir.vip_path;
            let bytes = std::slice::from_raw_parts(path.as_ptr().cast::<u8>(), size_of_val(path));
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            (end > 0).then(|| String::from_utf8_lossy(&bytes[..end]).into_owned())
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("bouncer supports Linux and macOS only");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_is_bounded() {
        let long = "x".repeat(200);
        let args: Vec<String> = (0..20).map(|_| long.clone()).collect();
        let s = short_argv(&args);
        assert!(s.len() < 8 * 90 + 10);
        assert!(s.ends_with(" ..."));
        assert_eq!(short_argv(&["a".into(), "b c".into()]), "a b c");
    }

    /// Environment copies (other processes' secrets) and the vault cipher wipe themselves.
    #[test]
    fn copies_of_secrets_are_wiped_on_drop() {
        fn wiped<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        let (_, env) = sys::args_env(std::process::id() as i32);
        wiped(&env.expect("own environment is readable"));
        use chacha20poly1305::aead::KeyInit;
        wiped(&chacha20poly1305::XChaCha20Poly1305::new(&[0u8; 32].into()));
    }

    #[test]
    fn attributes_own_process() {
        let a = Attributor::new(vec!["HOME".into()], 4);
        let me = std::process::id() as i32;
        let at = a.attribute(me);
        assert_eq!(at.chain[0].pid, me);
        assert_eq!(at.chain[0].uid, Some(crate::util::getuid()));
        assert!(at.chain.len() <= 4);
        assert!(at.chain[0].env, "{at:?}");
        assert_ne!(at.status, "unavailable");
        assert!(at.cwd.is_some());
        if std::env::var_os("HOME").is_some() {
            assert!(at.context.contains_key("HOME"));
        }
        assert!(a.attribute(0).is_unavailable());
        assert!(a.attribute(i32::MAX - 1).is_unavailable());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_procargs() {
        let mut buf = 2i32.to_ne_bytes().to_vec();
        buf.extend_from_slice(b"/bin/sh\0\0\0\0sh\0-c\0A=1\0B=2\0\0junk");
        let (argv, env) = sys::parse_procargs(&buf).unwrap();
        assert_eq!(argv, vec!["sh", "-c"]);
        assert_eq!(env, vec![b"A=1".to_vec(), b"B=2".to_vec()]);
    }
}
