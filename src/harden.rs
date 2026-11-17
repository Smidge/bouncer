//! Process hardening for the daemon: no core dumps, not dumpable/attachable where the OS
//! allows it, and memory locked so secrets are not written to swap.

/// Locking all future mappings (`MCL_FUTURE`) makes every later allocation fail once the
/// locked total passes RLIMIT_MEMLOCK, so it is only used when the limit leaves room.
#[cfg(target_os = "linux")]
const MLOCK_FUTURE_MIN: u64 = 512 << 20;

pub fn disable_core_dumps() {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: setrlimit reads a valid rlimit struct.
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
    }
    #[cfg(target_os = "linux")]
    // SAFETY: PR_SET_DUMPABLE takes a plain integer argument. It also stops other processes
    // running as the same uid from ptrace-attaching or reading /proc/<pid>/mem.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    // A file size limit should produce EFBIG (and a fail-closed audit log), not kill us.
    // SAFETY: ignoring a signal is always sound.
    unsafe {
        libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
    }
}

/// macOS: refuse debugger attachment (`PT_DENY_ATTACH`). Off by default because it also
/// blocks legitimate tools such as `sample` and crash reporting.
pub fn deny_debugger() {
    #[cfg(target_os = "macos")]
    // SAFETY: PT_DENY_ATTACH takes no address or data.
    unsafe {
        libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
    }
}

/// Raises RLIMIT_MEMLOCK's soft limit to the hard limit (root may also raise the hard limit).
pub fn raise_memlock() {
    // SAFETY: getrlimit/setrlimit read and write a valid rlimit struct.
    unsafe {
        let mut r: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut r) != 0 {
            return;
        }
        if libc::geteuid() == 0 {
            r.rlim_max = libc::RLIM_INFINITY;
        }
        r.rlim_cur = r.rlim_max;
        libc::setrlimit(libc::RLIMIT_MEMLOCK, &r);
    }
}

/// Locks memory so secrets are not swapped out. Returns a warning to print, if any.
pub fn lock_memory() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        raise_memlock();
        // SAFETY: getrlimit writes a valid rlimit struct.
        let limit = unsafe {
            let mut r: libc::rlimit = std::mem::zeroed();
            libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut r);
            r.rlim_cur
        };
        let future = limit == libc::RLIM_INFINITY || limit >= MLOCK_FUTURE_MIN;
        let flags = if future {
            libc::MCL_CURRENT | libc::MCL_FUTURE
        } else {
            libc::MCL_CURRENT
        };
        // SAFETY: mlockall takes flags only.
        if unsafe { libc::mlockall(flags) } != 0 {
            return Some(format!(
                "mlockall failed ({}); secrets may be swapped to disk. Raise the memlock limit \
                 (systemd: LimitMEMLOCK=infinity) or set mlock = false",
                std::io::Error::last_os_error()
            ));
        }
        if !future {
            return Some(format!(
                "RLIMIT_MEMLOCK is {} KiB, so only memory allocated so far is locked; later \
                 allocations can be swapped. Set LimitMEMLOCK=infinity (systemd) or ulimit -l unlimited",
                limit / 1024
            ));
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        // macOS has no working mlockall; its swap is encrypted by default.
        None
    }
}
