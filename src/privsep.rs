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
//!    answers one question: "attribute pid X". It never sees the key, the vault or a client
//!    socket.
//! 2. The main process reads root-only credentials (systemd `$CREDENTIALS_DIRECTORY`), hands
//!    the socket directory to the `bouncer` user, then drops to that uid/gid with no
//!    supplementary groups and no capabilities, and verifies it cannot get root back.
//!
//! The daemon talks to the inspector over *channels*: socketpairs the inspector creates on
//! request (a byte on the control socket; the fd comes back with `SCM_RIGHTS`) and serves on
//! a thread each, so several connections are attributed at once (up to `MAX_CHANNELS`).
//! Every request carries an id that the reply must echo. A channel that times out, breaks or
//! answers out of turn is closed and never reused, so a late reply cannot be taken for the
//! answer to a later request. If the control socket fails, the inspector is down: every
//! attribution is `unavailable` (so get/exec are denied while `require_attribution = true`)
//! and `status` and `doctor` say so. It cannot be restarted from inside the daemon, which no
//! longer has the privileges to create it; restart the service.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::err;
use crate::peer::{Attribution, Attributor};
use crate::util::Result;

const MAGIC: &[u8; 4] = b"BNCI";
/// 2: requests carry an id, replies are `id, length, JSON`; channels come over `SCM_RIGHTS`.
const VERSION: u32 = 2;
const MAX_REPLY: usize = 256 * 1024;
/// Channels the daemon keeps to the inspector, so this many connections can be attributed
/// at once.
pub const MAX_CHANNELS: usize = 8;
/// Channels the inspector serves at once (retired ones may still be finishing a request).
const MAX_HELPER_CHANNELS: usize = 64;
const RPC_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// Asks the inspector for a new channel.
    control: Mutex<UnixStream>,
    idle: Mutex<Vec<UnixStream>>,
    returned: Condvar,
    /// Channels that exist (idle or in use).
    open: AtomicUsize,
    next_id: AtomicU32,
    /// The inspector's pid (0 when it is a thread, in tests).
    pid: libc::pid_t,
    /// Why the inspector is unusable, once it is.
    down: Mutex<Option<String>>,
    timeout: Duration,
}

impl Inspector {
    fn new(control: UnixStream, pid: libc::pid_t, timeout: Duration) -> Result<Inspector> {
        control.set_read_timeout(Some(timeout))?;
        control.set_write_timeout(Some(timeout))?;
        Ok(Inspector {
            control: Mutex::new(control),
            idle: Mutex::new(Vec::new()),
            returned: Condvar::new(),
            open: AtomicUsize::new(0),
            next_id: AtomicU32::new(1),
            pid,
            down: Mutex::new(None),
            timeout,
        })
    }

    pub fn attribute(&self, pid: i32) -> Attribution {
        let ch = match self.checkout() {
            Ok(c) => c,
            Err(e) => return Attribution::unavailable(e),
        };
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        match rpc(&ch, id, pid) {
            Ok(at) => {
                self.idle.lock().unwrap_or_else(|e| e.into_inner()).push(ch);
                self.returned.notify_one();
                at
            }
            Err(e) => {
                // Never reuse it: a late reply would be read as the answer to the next request.
                drop(ch);
                self.open.fetch_sub(1, Ordering::AcqRel);
                self.returned.notify_one();
                Attribution::unavailable(format!("attribution helper failed: {e}"))
            }
        }
    }

    /// An idle channel, a new one, or (when `MAX_CHANNELS` are busy) the next one returned.
    fn checkout(&self) -> std::result::Result<UnixStream, String> {
        if let Some(why) = self.health() {
            return Err(format!("the attribution helper is down: {why}"));
        }
        let deadline = Instant::now() + self.timeout;
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(c) = idle.pop() {
                return Ok(c);
            }
            if self.open.load(Ordering::Acquire) < MAX_CHANNELS {
                self.open.fetch_add(1, Ordering::AcqRel);
                drop(idle);
                return self.new_channel().map_err(|e| {
                    self.open.fetch_sub(1, Ordering::AcqRel);
                    if e.kind() == std::io::ErrorKind::ResourceBusy {
                        return format!("the attribution helper is busy: {e}");
                    }
                    let why = format!("cannot open a channel to it: {e}");
                    *self.down.lock().unwrap_or_else(|e| e.into_inner()) = Some(why.clone());
                    format!("the attribution helper is down: {why}")
                });
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err("every attribution helper channel is busy".into());
            }
            idle = self
                .returned
                .wait_timeout(idle, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    fn new_channel(&self) -> std::io::Result<UnixStream> {
        let ctl = self.control.lock().unwrap_or_else(|e| e.into_inner());
        (&*ctl).write_all(b"N")?;
        let fd = recv_fd(&ctl)?;
        let s = UnixStream::from(fd);
        s.set_read_timeout(Some(self.timeout))?;
        s.set_write_timeout(Some(self.timeout))?;
        Ok(s)
    }

    /// None while the inspector works, else why it does not.
    pub fn health(&self) -> Option<String> {
        let mut down = self.down.lock().unwrap_or_else(|e| e.into_inner());
        if down.is_none() && self.pid > 0 {
            let mut status = 0;
            // SAFETY: waitpid on our own child with a valid out-pointer.
            if unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) } == self.pid {
                *down = Some(format!("it exited (wait status {status:#x})"));
            }
        }
        down.clone()
    }
}

/// One request on one channel; the reply must carry the request's id.
fn rpc(s: &UnixStream, id: u32, pid: i32) -> std::io::Result<Attribution> {
    let mut req = [0u8; 16];
    req[..4].copy_from_slice(MAGIC);
    req[4..8].copy_from_slice(&VERSION.to_le_bytes());
    req[8..12].copy_from_slice(&pid.to_le_bytes());
    req[12..16].copy_from_slice(&id.to_le_bytes());
    let mut s = s;
    s.write_all(&req)?;
    let mut hdr = [0u8; 8];
    s.read_exact(&mut hdr)?;
    let got = u32::from_le_bytes(hdr[..4].try_into().expect("4 bytes"));
    if got != id {
        return Err(std::io::Error::other(format!(
            "reply for request {got}, expected {id}"
        )));
    }
    let len = u32::from_le_bytes(hdr[4..].try_into().expect("4 bytes")) as usize;
    if len > MAX_REPLY {
        return Err(std::io::Error::other("reply too large"));
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).map_err(|_| std::io::Error::other("malformed reply"))
}

/// Room for one fd in a control message, aligned for `cmsghdr`.
#[repr(C, align(8))]
struct CmsgBuf([u8; 64]);

/// Sends one byte with `fd` attached (`SCM_RIGHTS`).
fn send_fd(sock: &UnixStream, fd: RawFd) -> std::io::Result<()> {
    let mut byte = *b"F";
    let mut cbuf = CmsgBuf([0; 64]);
    // SAFETY: msghdr is plain data; iov and the control buffer outlive the sendmsg call, and
    // the buffer is large and aligned enough for one cmsghdr carrying one int.
    unsafe {
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let space = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as usize;
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.0.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>(), fd);
        if libc::sendmsg(sock.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) != 1 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Receives the fd `send_fd` sent.
fn recv_fd(sock: &UnixStream) -> std::io::Result<OwnedFd> {
    let mut byte = [0u8];
    let mut cbuf = CmsgBuf([0; 64]);
    // SAFETY: as in send_fd; the kernel fills the buffers, and only a well-formed SCM_RIGHTS
    // message with one int is read back.
    unsafe {
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.0.as_mut_ptr().cast();
        msg.msg_controllen = cbuf.0.len() as _;
        let n = libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC);
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
            || (*cmsg).cmsg_len as usize
                != libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ResourceBusy,
                "it is still serving too many channels",
            ));
        }
        let fd = std::ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<RawFd>());
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

type Handler = Arc<dyn Fn(i32) -> Attribution + Send + Sync>;

/// The inspector's side: makes a channel for every byte on `control`, until it closes.
fn serve_control(mut control: UnixStream, handler: Handler) -> Result<()> {
    let live = Arc::new(AtomicUsize::new(0));
    let mut b = [0u8; 1];
    loop {
        match control.read(&mut b) {
            Ok(0) | Err(_) => return Ok(()), // the daemon went away
            Ok(_) if b[0] != b'N' => return Err(err!("malformed control request; exiting")),
            Ok(_) => {}
        }
        if live.load(Ordering::Acquire) >= MAX_HELPER_CHANNELS {
            // A byte without a channel: the daemon reports it and tries again later.
            control.write_all(b"X")?;
            continue;
        }
        let (ours, theirs) = UnixStream::pair()?;
        send_fd(&control, theirs.as_raw_fd())?;
        drop(theirs);
        live.fetch_add(1, Ordering::AcqRel);
        let (h, l) = (handler.clone(), live.clone());
        let spawned = std::thread::Builder::new()
            .name("inspector".into())
            .stack_size(512 * 1024)
            .spawn(move || {
                serve_channel(ours, &*h);
                l.fetch_sub(1, Ordering::AcqRel);
            });
        if spawned.is_err() {
            live.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Answers requests on one channel until it closes or a request is malformed.
fn serve_channel(mut sock: UnixStream, handler: &(dyn Fn(i32) -> Attribution + Send + Sync)) {
    let mut req = [0u8; 16];
    loop {
        if sock.read_exact(&mut req).is_err() {
            return;
        }
        if &req[..4] != MAGIC || req[4..8] != VERSION.to_le_bytes() {
            return;
        }
        let pid = i32::from_le_bytes(req[8..12].try_into().expect("4 bytes"));
        let at = handler(pid);
        let mut body = serde_json::to_vec(&at).unwrap_or_default();
        if body.len() > MAX_REPLY {
            body = serde_json::to_vec(&Attribution::unavailable("attribution too large"))
                .unwrap_or_default();
        }
        let mut out = req[12..16].to_vec(); // the request id
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        if sock.write_all(&out).is_err() {
            return;
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
    Inspector::new(parent, pid, RPC_TIMEOUT)
}

fn inspector_main(control: UnixStream, uid: u32, gid: u32, attributor: Attributor) -> Result<()> {
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
    serve_control(control, Arc::new(move |pid| attributor.attribute(pid)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An inspector served by a thread, answering with `handler`.
    fn inspector(handler: Handler, timeout: Duration) -> Inspector {
        let (a, b) = UnixStream::pair().unwrap();
        std::thread::spawn(move || serve_control(b, handler));
        Inspector::new(a, 0, timeout).unwrap()
    }

    fn named(pid: i32) -> Attribution {
        Attribution {
            status: "ok".into(),
            cwd: Some(format!("pid {pid}")),
            ..Default::default()
        }
    }

    #[test]
    fn a_late_reply_is_never_taken_for_the_next_answer() {
        let i = inspector(
            Arc::new(|pid| {
                if pid == 42 {
                    std::thread::sleep(Duration::from_millis(800));
                }
                named(pid)
            }),
            Duration::from_millis(200),
        );
        let slow = i.attribute(42);
        assert!(slow.is_unavailable(), "{slow:?}");
        assert!(slow.error.unwrap().contains("helper failed"));
        // The timed-out channel was retired; the next request is answered for its own pid,
        // including after the slow reply has arrived.
        for pid in [7, 8] {
            assert_eq!(
                i.attribute(pid).cwd.as_deref(),
                Some(&*format!("pid {pid}"))
            );
            std::thread::sleep(Duration::from_millis(500));
        }
        assert!(i.health().is_none());
        assert_eq!(i.open.load(Ordering::Acquire), 1);
    }

    #[test]
    fn a_reply_with_another_id_retires_the_channel() {
        // A helper whose first reply carries the wrong id.
        let (a, b) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let mut b = b;
            let mut n = [0u8; 1];
            let mut first = true;
            while b.read(&mut n).is_ok_and(|k| k == 1) {
                let (ours, theirs) = UnixStream::pair().unwrap();
                send_fd(&b, theirs.as_raw_fd()).unwrap();
                let bad = std::mem::replace(&mut first, false);
                std::thread::spawn(move || {
                    let mut s = ours;
                    let mut req = [0u8; 16];
                    while s.read_exact(&mut req).is_ok() {
                        let id = u32::from_le_bytes(req[12..16].try_into().unwrap());
                        let pid = i32::from_le_bytes(req[8..12].try_into().unwrap());
                        let body = serde_json::to_vec(&named(pid)).unwrap();
                        let id = if bad { id + 1000 } else { id };
                        let mut out = id.to_le_bytes().to_vec();
                        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
                        out.extend_from_slice(&body);
                        s.write_all(&out).unwrap();
                    }
                });
            }
        });
        let i = Inspector::new(a, 0, Duration::from_secs(2)).unwrap();
        let e = i.attribute(5).error.unwrap();
        assert!(e.contains("expected"), "{e}");
        assert_eq!(i.attribute(6).cwd.as_deref(), Some("pid 6"));
    }

    #[test]
    fn channels_attribute_in_parallel() {
        let i = Arc::new(inspector(
            Arc::new(|pid| {
                std::thread::sleep(Duration::from_millis(300));
                named(pid)
            }),
            Duration::from_secs(5),
        ));
        let t = Instant::now();
        let handles: Vec<_> = (0..4)
            .map(|p| {
                let i = i.clone();
                std::thread::spawn(move || i.attribute(p).cwd)
            })
            .collect();
        for (p, h) in handles.into_iter().enumerate() {
            assert_eq!(h.join().unwrap(), Some(format!("pid {p}")));
        }
        assert!(
            t.elapsed() < Duration::from_millis(900),
            "{:?}",
            t.elapsed()
        );
    }

    #[test]
    fn a_dead_helper_is_reported() {
        let (a, b) = UnixStream::pair().unwrap();
        drop(b);
        let i = Inspector::new(a, 0, Duration::from_secs(1)).unwrap();
        let at = i.attribute(1);
        assert!(at.is_unavailable());
        assert!(at.error.unwrap().contains("helper is down"));
        assert!(i.health().is_some());
        // And stays down without trying again.
        assert!(i.attribute(1).error.unwrap().contains("helper is down"));
    }
}
