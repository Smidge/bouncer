//! Privilege separation for dedicated-user mode (Linux), in the style of OpenSSH.
//!
//! Reading another user's `/proc/<pid>/environ` needs both `CAP_SYS_PTRACE` (the ptrace
//! access check) and `CAP_DAC_READ_SEARCH` (the file is mode 0400, owned by that user). The
//! daemon must not hold those while it also holds decrypted secrets and talks to clients, so
//! when `bouncer serve` starts as root with `user = "bouncer"`:
//!
//! 1. Before any thread or secret exists, it forks an *inspector*. The inspector drops every
//!    capability from its bounding set except those two, switches to the `bouncer` uid/gid
//!    keeping only those two as permitted and effective, sets `no_new_privs`, and then only
//!    answers one question over a socketpair: "attribute pid X" (16-byte request, length-
//!    prefixed JSON reply). It never sees the key, the vault or a client socket.
//! 2. The main process reads root-only credentials (systemd `$CREDENTIALS_DIRECTORY`), hands
//!    the socket directory to the `bouncer` user, then drops to that uid/gid with no
//!    supplementary groups and no capabilities, and verifies it cannot get root back.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::Duration;

use crate::err;
use crate::peer::{Attribution, Attributor};
use crate::util::Result;

const MAGIC: &[u8; 4] = b"BNCI";
const VERSION: u32 = 1;
const MAX_REPLY: usize = 256 * 1024;

const CAP_DAC_READ_SEARCH: u32 = 2;
const CAP_SYS_PTRACE: u32 = 19;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn capset(effective: u32, permitted: u32) -> std::io::Result<()> {
    let hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [
        CapData {
            effective,
            permitted,
            inheritable: 0,
        },
        CapData::default(),
    ];
    // SAFETY: hdr and data match the kernel's v3 capability structs.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &hdr, data.as_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn capget() -> std::io::Result<(u64, u64)> {
    let hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: as for capset; the kernel fills data.
    let rc = unsafe { libc::syscall(libc::SYS_capget, &hdr, data.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let join = |lo: u32, hi: u32| u64::from(lo) | (u64::from(hi) << 32);
    Ok((
        join(data[0].effective, data[1].effective),
        join(data[0].permitted, data[1].permitted),
    ))
}

fn check(rc: libc::c_int, what: &str) -> Result<()> {
    if rc != 0 {
        return Err(err!("{what}: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Switches to uid/gid with only the given supplementary groups.
fn set_ids(uid: u32, gid: u32, groups: &[u32]) -> Result<()> {
    // SAFETY: groups is a valid slice of gids; the rest are plain integer syscalls.
    unsafe {
        check(
            libc::setgroups(groups.len() as _, groups.as_ptr()),
            "setgroups",
        )?;
        check(libc::setresgid(gid, gid, gid), "setresgid")?;
        check(libc::setresuid(uid, uid, uid), "setresuid")?;
    }
    let (mut r, mut e, mut s) = (0, 0, 0);
    // SAFETY: out-pointers are valid locals.
    unsafe { libc::getresuid(&mut r, &mut e, &mut s) };
    if (r, e, s) != (uid, uid, uid) {
        return Err(err!("uid change did not stick"));
    }
    // SAFETY: as above.
    unsafe { libc::getresgid(&mut r, &mut e, &mut s) };
    if (r, e, s) != (gid, gid, gid) {
        return Err(err!("gid change did not stick"));
    }
    Ok(())
}

/// Drops to `uid`/`gid` for good: no capabilities and no way back to root. The only
/// supplementary group kept is `socket_group`, so the daemon can give its socket that group.
pub fn drop_privileges(uid: u32, gid: u32, socket_group: Option<u32>) -> Result<()> {
    // SAFETY: prctl with integer arguments.
    unsafe {
        libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0);
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        );
    }
    let groups: Vec<u32> = socket_group.into_iter().collect();
    set_ids(uid, gid, &groups)?;
    // SAFETY: as above.
    unsafe {
        check(
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
            "no_new_privs",
        )?;
        if libc::setuid(0) == 0 || libc::seteuid(0) == 0 {
            return Err(err!("privilege drop failed: could regain root"));
        }
    }
    let (eff, perm) = capget().map_err(|e| err!("capget: {e}"))?;
    if eff != 0 || perm != 0 {
        return Err(err!(
            "privilege drop failed: capabilities remain ({eff:#x}/{perm:#x})"
        ));
    }
    Ok(())
}

/// The main daemon's handle on the inspector.
pub struct Inspector {
    sock: Mutex<UnixStream>,
}

impl Inspector {
    pub fn attribute(&self, pid: i32) -> Attribution {
        let mut s = self.sock.lock().unwrap_or_else(|e| e.into_inner());
        let mut req = [0u8; 16];
        req[..4].copy_from_slice(MAGIC);
        req[4..8].copy_from_slice(&VERSION.to_le_bytes());
        req[8..12].copy_from_slice(&pid.to_le_bytes());
        let r = (|| -> std::io::Result<Vec<u8>> {
            s.write_all(&req)?;
            let mut len = [0u8; 4];
            s.read_exact(&mut len)?;
            let len = u32::from_le_bytes(len) as usize;
            if len > MAX_REPLY {
                return Err(std::io::Error::other("reply too large"));
            }
            let mut buf = vec![0u8; len];
            s.read_exact(&mut buf)?;
            Ok(buf)
        })();
        match r.map(|b| serde_json::from_slice::<Attribution>(&b)) {
            Ok(Ok(a)) => a,
            Ok(Err(_)) => Attribution::unavailable("attribution helper sent a malformed reply"),
            Err(e) => Attribution::unavailable(format!("attribution helper failed: {e}")),
        }
    }
}

/// Forks the inspector. Must run before any other thread exists.
pub fn spawn_inspector(uid: u32, gid: u32, attributor: Attributor) -> Result<Inspector> {
    let (parent, child) = UnixStream::pair()?;
    // SAFETY: the process is single-threaded here, so the child may allocate freely.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(err!("fork: {}", std::io::Error::last_os_error()));
    }
    if pid == 0 {
        drop(parent);
        let code = match inspector_main(child, uid, gid, attributor) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("bouncer inspector: {e}");
                1
            }
        };
        // SAFETY: exit without running the parent's atexit handlers or destructors.
        unsafe { libc::_exit(code) };
    }
    drop(child);
    parent.set_read_timeout(Some(Duration::from_secs(5)))?;
    parent.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(Inspector {
        sock: Mutex::new(parent),
    })
}

fn inspector_main(mut sock: UnixStream, uid: u32, gid: u32, attributor: Attributor) -> Result<()> {
    let keep = (1u64 << CAP_DAC_READ_SEARCH) | (1u64 << CAP_SYS_PTRACE);
    // SAFETY: prctl calls with integer arguments.
    unsafe {
        check(
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0),
            "pdeathsig",
        )?;
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        // Shrink the bounding set while we still have CAP_SETPCAP.
        for cap in 0..64u64 {
            if keep & (1 << cap) == 0 {
                libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0);
            }
        }
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        );
        check(libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0), "keepcaps")?;
    }
    set_ids(uid, gid, &[])?;
    capset(keep as u32, keep as u32).map_err(|e| err!("capset: {e}"))?;
    // SAFETY: as above.
    unsafe {
        libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0);
        check(
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0),
            "no_new_privs",
        )?;
    }
    let (eff, perm) = capget().map_err(|e| err!("capget: {e}"))?;
    if eff != keep || perm != keep {
        return Err(err!("unexpected capabilities {eff:#x}/{perm:#x}"));
    }
    let mut req = [0u8; 16];
    loop {
        if sock.read_exact(&mut req).is_err() {
            return Ok(()); // the daemon went away
        }
        if &req[..4] != MAGIC || req[4..8] != VERSION.to_le_bytes() || req[12..16] != [0, 0, 0, 0] {
            return Err(err!("malformed request; exiting"));
        }
        let pid = i32::from_le_bytes(req[8..12].try_into().expect("4 bytes"));
        let at = attributor.attribute(pid);
        let mut body = serde_json::to_vec(&at).unwrap_or_default();
        if body.len() > MAX_REPLY {
            body = serde_json::to_vec(&Attribution::unavailable("attribution too large"))
                .unwrap_or_default();
        }
        sock.write_all(&(body.len() as u32).to_le_bytes())?;
        sock.write_all(&body)?;
    }
}
