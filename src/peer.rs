//! Caller attribution from the OS: peer credentials of the socket and the process ancestry.
//!
//! Nothing here trusts what the client says about itself. The peer pid/uid come from the
//! kernel (`SO_PEERCRED` on Linux, `getpeereid` + `LOCAL_PEERPID` on macOS), and context
//! variables such as `CLAUDE_CODE_SESSION_ID` are taken from the *oldest* ancestor that has
//! them, so a child process cannot spoof them by setting the variable itself.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

use serde::Serialize;

#[derive(Clone, Copy, Debug, Serialize)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: i32,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChainEntry {
    pub pid: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argv: Option<String>,
    /// False when the process environment could not be read.
    #[serde(skip_serializing_if = "is_true")]
    pub env: bool,
}

fn is_true(b: &bool) -> bool {
    *b
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct CtxValue {
    pub value: String,
    pub pid: i32,
}

#[derive(Clone, Debug, Default)]
pub struct Attribution {
    /// "ok", "partial" (some same-uid ancestor's environment was unreadable) or "unavailable".
    pub status: &'static str,
    pub cwd: Option<String>,
    pub context: BTreeMap<String, CtxValue>,
    pub chain: Vec<ChainEntry>,
}

pub fn peer_cred(stream: &UnixStream) -> io::Result<PeerCred> {
    sys::peer_cred(stream.as_raw_fd())
}

/// Cheap per-process facts used to walk the tree and key the cache.
struct Basic {
    ppid: i32,
    uid: Option<u32>,
    start: u64,
}

/// Facts that never change for a given (pid, start time), so they are cached.
struct Details {
    exe: Option<String>,
    argv: Option<String>,
    /// Configured context variables found in the initial environment; None if unreadable.
    ctx: Option<Vec<(String, String)>>,
}

pub struct Attributor {
    vars: Vec<String>,
    depth: usize,
    cache: Mutex<HashMap<(i32, u64), Arc<Details>>>,
}

const CACHE_MAX: usize = 4096;

impl Attributor {
    pub fn new(vars: Vec<String>, depth: usize) -> Attributor {
        Attributor {
            vars,
            depth,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn details(&self, pid: i32, start: u64) -> Arc<Details> {
        if let Some(d) = self.cache.lock().unwrap().get(&(pid, start)) {
            return d.clone();
        }
        let (args, env) = sys::args_env(pid);
        // An empty environment means it was hidden from us (macOS does this for Apple
        // platform binaries such as /bin/sh and /bin/zsh), so treat it as unreadable.
        let ctx = env.filter(|e| !e.is_empty()).map(|env| {
            let mut found = Vec::new();
            for entry in &env {
                let Some(eq) = entry.iter().position(|&b| b == b'=') else {
                    continue;
                };
                let (k, v) = (&entry[..eq], &entry[eq + 1..]);
                if let Some(var) = self.vars.iter().find(|var| var.as_bytes() == k) {
                    found.push((var.clone(), String::from_utf8_lossy(v).into_owned()));
                }
            }
            found
        });
        let exe = sys::exe(pid).or_else(|| args.as_ref().and_then(|a| a.first().cloned()));
        let d = Arc::new(Details {
            exe,
            argv: args.as_deref().map(short_argv),
            ctx,
        });
        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= CACHE_MAX {
            cache.clear();
        }
        cache.insert((pid, start), d.clone());
        d
    }

    /// Walks from `pid` up through its ancestors and gathers attribution.
    pub fn attribute(&self, pid: i32) -> Attribution {
        let mut chain = Vec::new();
        let mut ctxs = Vec::new();
        let mut cur = pid;
        while chain.len() < self.depth && cur > 0 {
            let Some(b) = sys::basic(cur) else { break };
            let d = self.details(cur, b.start);
            chain.push(ChainEntry {
                pid: cur,
                uid: b.uid,
                exe: d.exe.clone(),
                argv: d.argv.clone(),
                env: d.ctx.is_some(),
            });
            ctxs.push(d);
            if cur == 1 || b.ppid == cur {
                break;
            }
            cur = b.ppid;
        }
        let mut context = BTreeMap::new();
        // Oldest ancestor wins: iterate from the top of the tree down.
        for (entry, d) in chain.iter().zip(&ctxs).rev() {
            for (k, v) in d.ctx.iter().flatten() {
                context.entry(k.clone()).or_insert(CtxValue {
                    value: v.clone(),
                    pid: entry.pid,
                });
            }
        }
        let peer_uid = chain.first().and_then(|e| e.uid);
        let status = match chain.first() {
            None => "unavailable",
            Some(e) if !e.env => "unavailable",
            _ if chain.iter().any(|e| e.uid == peer_uid && !e.env) => "partial",
            _ => "ok",
        };
        Attribution {
            status,
            cwd: sys::cwd(pid),
            context,
            chain,
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
        if a.chars().count() > MAX_ARG {
            s.extend(a.chars().take(MAX_ARG));
            s.push_str("...");
        } else {
            s.push_str(a);
        }
    }
    s
}

#[cfg(target_os = "linux")]
mod sys {
    use super::{Basic, PeerCred};
    use std::fs;
    use std::io;
    use std::os::unix::fs::MetadataExt;

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

    pub fn args_env(pid: i32) -> (Option<Vec<String>>, Option<Vec<Vec<u8>>>) {
        let args = fs::read(format!("/proc/{pid}/cmdline")).ok().map(|d| {
            split_nul(&d)
                .iter()
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect()
        });
        let env = fs::read(format!("/proc/{pid}/environ"))
            .ok()
            .map(|d| split_nul(&d));
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
    use super::{Basic, PeerCred};
    use std::io;
    use std::mem::{size_of, zeroed};
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
                return Err(io::Error::last_os_error());
            }
            Ok(PeerCred { uid, gid, pid })
        }
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

    /// argv and environment via `sysctl(KERN_PROCARGS2)`; only works for same-uid processes
    /// (or as root).
    pub fn args_env(pid: i32) -> (Option<Vec<String>>, Option<Vec<Vec<u8>>>) {
        let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
        let mut buf = vec![0u8; argmax()];
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
        buf.truncate(size);
        parse_procargs(&buf)
            .map(|(a, e)| (Some(a), Some(e)))
            .unwrap_or((None, None))
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
