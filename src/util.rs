//! Small helpers: error type, time formatting, encodings, and file operations that do not
//! follow symlinks or trust directories other users can write to.

use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

/// A plain error message. Messages must never contain secret values.
#[derive(Debug)]
pub struct Error(pub String);

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error(e.to_string())
    }
}

#[macro_export]
macro_rules! err {
    ($($arg:tt)*) => { $crate::util::Error(format!($($arg)*)) };
}

/// Adds the path to an I/O error.
pub fn ctx<T>(r: io::Result<T>, what: &str, path: &Path) -> Result<T> {
    r.map_err(|e| Error(format!("{what} {}: {e}", path.display())))
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Days since 1970-01-01 to (year, month, day). Howard Hinnant's civil_from_days.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// (year, month, day) to days since 1970-01-01. Inverse of `civil_from_days`.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Milliseconds since the epoch to `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn rfc3339_ms(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let (y, mo, d) = civil_from_days(secs.div_euclid(86_400));
    let sod = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        sod / 3600,
        sod % 3600 / 60,
        sod % 60,
        ms.rem_euclid(1000)
    )
}

/// Parses the exact format `rfc3339_ms` writes. Returns None for anything else.
pub fn parse_rfc3339_ms(ts: &str) -> Option<i64> {
    let b = ts.as_bytes();
    if b.len() != 24 || &b[4..5] != b"-" || b[10] != b'T' || b[23] != b'Z' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let s = ts.get(r)?;
        s.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| s.parse().ok())?
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, s, ms) = (num(11..13)?, num(14..16)?, num(17..19)?, num(20..23)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    let days = days_from_civil(y, mo as u32, d as u32);
    Some(((days * 86_400 + h * 3600 + mi * 60 + s) * 1000) + ms)
}

pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

pub fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                s.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    use hmac::{KeyInit, Mac};
    let mut m = hmac::Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    m.finalize().into_bytes().into()
}

/// Compares two byte strings in constant time (for equal lengths).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| err!("random number generator failed: {e}"))?;
    Ok(buf)
}

pub fn random_hex<const N: usize>() -> Result<String> {
    Ok(hex(&random_bytes::<N>()?))
}

/// Escapes control characters (including newlines, ESC and bidi overrides) for terminal
/// output. The stored data stays raw; only what is printed is escaped.
pub fn escape(s: &str) -> std::borrow::Cow<'_, str> {
    let bad = |c: char| {
        c.is_control()
            || ('\u{202a}'..='\u{202e}').contains(&c)
            || ('\u{2066}'..='\u{2069}').contains(&c)
    };
    if !s.chars().any(bad) {
        return s.into();
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if bad(c) => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out.into()
}

/// Truncates to at most `max` characters, appending "..." when cut.
pub fn cap(s: &str, max: usize) -> String {
    match s.char_indices().nth(max) {
        None => s.to_string(),
        Some((i, _)) => format!("{}...", &s[..i]),
    }
}

pub fn getuid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

pub fn geteuid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn cstr(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn cvt(rc: libc::c_int) -> io::Result<libc::c_int> {
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

/// Splits a path into its parent directory and final component.
pub fn split_path(path: &Path) -> Result<(PathBuf, &OsStr)> {
    let name = path
        .file_name()
        .ok_or_else(|| err!("{} has no file name", path.display()))?;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    Ok((parent, name))
}

/// Who may own a file bouncer reads its key or credentials from.
pub fn trusted_owner(uid: u32) -> bool {
    uid == geteuid() || uid == 0
}

/// Checks a file holding key material: a regular file owned by us (or root), mode exactly
/// 0600 or 0400.
pub fn check_secret_file(meta: &fs::Metadata, path: &Path) -> Result<()> {
    let mode = meta.mode() & 0o7777;
    if !meta.file_type().is_file() {
        return Err(err!("{} is not a regular file", path.display()));
    }
    if !trusted_owner(meta.uid()) {
        return Err(err!(
            "{} is owned by uid {}; it must be owned by uid {} (or root)",
            path.display(),
            meta.uid(),
            geteuid()
        ));
    }
    if mode != 0o600 && mode != 0o400 {
        return Err(err!(
            "{} has mode {mode:04o}; it must be 0600 or 0400 (run: chmod 600 {})",
            path.display(),
            path.display()
        ));
    }
    Ok(())
}

/// Checks a data file bouncer writes (vault, audit log): regular, owned by us, no access for
/// group or others.
pub fn check_data_file(meta: &fs::Metadata, path: &Path) -> Result<()> {
    if !meta.file_type().is_file() {
        return Err(err!("{} is not a regular file", path.display()));
    }
    if meta.uid() != geteuid() {
        return Err(err!(
            "{} is owned by uid {}, not by this daemon's uid {}",
            path.display(),
            meta.uid(),
            geteuid()
        ));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(err!(
            "{} has mode {:04o}; group and others must have no access (run: chmod 600 {})",
            path.display(),
            meta.mode() & 0o7777,
            path.display()
        ));
    }
    Ok(())
}

/// Opens an existing file for reading without following a symlink in the last component.
pub fn open_nofollow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

/// Reads a small key or credential file after checking owner and mode on the open fd.
pub fn read_secret_file(path: &Path, max: u64) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    use std::io::Read;
    let f = ctx(open_nofollow(path), "cannot open", path)?;
    let meta = ctx(f.metadata(), "cannot stat", path)?;
    check_secret_file(&meta, path)?;
    let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(128));
    ctx(f.take(max + 1).read_to_end(&mut buf), "cannot read", path)?;
    if buf.len() as u64 > max {
        return Err(err!("{} is larger than {max} bytes", path.display()));
    }
    Ok(buf)
}

/// An open, verified directory. Files inside are opened relative to its descriptor with
/// `O_NOFOLLOW`, so a directory swapped in later cannot redirect them.
pub struct Dir {
    file: File,
    path: PathBuf,
}

impl Dir {
    /// Creates `path` (and missing parents, mode 0700) if needed, then opens and verifies it:
    /// a real directory (not a symlink), owned by us, not writable by group or others, and
    /// with no group/other access at all when `private`.
    pub fn secure(path: &Path, private: bool) -> Result<Dir> {
        let created = match fs::symlink_metadata(path) {
            Ok(_) => false,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                ctx(
                    fs::DirBuilder::new()
                        .recursive(true)
                        .mode(0o700)
                        .create(path),
                    "cannot create directory",
                    path,
                )?;
                true
            }
            Err(e) => return Err(err!("cannot stat {}: {e}", path.display())),
        };
        let dir = Dir::open(path, private)?;
        if created {
            ctx(
                dir.file.set_permissions(fs::Permissions::from_mode(0o700)),
                "cannot chmod",
                path,
            )?;
        }
        Ok(dir)
    }

    /// Opens and verifies an existing directory (see `secure`).
    pub fn open(path: &Path, private: bool) -> Result<Dir> {
        let file = ctx(
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path),
            "cannot open directory",
            path,
        )
        .map_err(|e| match fs::symlink_metadata(path) {
            Ok(m) if m.file_type().is_symlink() => {
                err!(
                    "{} is a symlink; bouncer needs a real directory",
                    path.display()
                )
            }
            _ => e,
        })?;
        let meta = ctx(file.metadata(), "cannot stat", path)?;
        check_dir(&meta, path, private)?;
        Ok(Dir {
            file,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn fd(&self) -> i32 {
        self.file.as_raw_fd()
    }

    pub fn metadata(&self) -> io::Result<fs::Metadata> {
        self.file.metadata()
    }

    /// `openat` with `O_NOFOLLOW | O_CLOEXEC` added. `name` must be a single component.
    pub fn open_at(&self, name: &OsStr, flags: libc::c_int, mode: u32) -> io::Result<File> {
        if name.as_bytes().contains(&b'/') || name.is_empty() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let c = cstr(name)?;
        // SAFETY: c is a valid NUL-terminated string and the dir fd is open.
        let fd = cvt(unsafe {
            libc::openat(
                self.fd(),
                c.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode as libc::c_uint,
            )
        })?;
        // SAFETY: fd was just returned by openat and is owned by nobody else.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Creates a new file; fails if anything (including a symlink) already has that name.
    pub fn create_excl(&self, name: &OsStr, mode: u32) -> io::Result<File> {
        let f = self.open_at(name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, mode)?;
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        Ok(f)
    }

    /// `lstat` of an entry; None if it does not exist.
    pub fn lstat(&self, name: &OsStr) -> io::Result<Option<libc::stat>> {
        let c = cstr(name)?;
        // SAFETY: st is plain data; c is NUL-terminated; the dir fd is open.
        unsafe {
            let mut st: libc::stat = std::mem::zeroed();
            if libc::fstatat(self.fd(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) == 0 {
                return Ok(Some(st));
            }
        }
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(e)
        }
    }

    pub fn unlink(&self, name: &OsStr) -> io::Result<()> {
        let c = cstr(name)?;
        // SAFETY: c is NUL-terminated; the dir fd is open.
        cvt(unsafe { libc::unlinkat(self.fd(), c.as_ptr(), 0) }).map(drop)
    }

    /// Changes the group of an entry without following symlinks.
    pub fn chown(&self, name: &OsStr, uid: Option<u32>, gid: Option<u32>) -> io::Result<()> {
        let c = cstr(name)?;
        let (u, g) = (uid.unwrap_or(u32::MAX), gid.unwrap_or(u32::MAX));
        // SAFETY: c is NUL-terminated; the dir fd is open; -1 (u32::MAX) leaves an id unchanged.
        cvt(unsafe { libc::fchownat(self.fd(), c.as_ptr(), u, g, libc::AT_SYMLINK_NOFOLLOW) })
            .map(drop)
    }

    pub fn sync(&self) -> io::Result<()> {
        self.file.sync_all()
    }

    /// Writes `data` to `name` atomically: a randomly named temp file created with
    /// `O_CREAT | O_EXCL | O_NOFOLLOW` at `mode`, fsync, rename, fsync the directory.
    pub fn write_atomic(&self, name: &OsStr, data: &[u8], mode: u32) -> Result<()> {
        let mut tmp = std::ffi::OsString::from(".");
        tmp.push(name);
        tmp.push(format!(".{}.tmp", random_hex::<8>()?));
        let target = self.path.join(name);
        let write = || -> io::Result<()> {
            let mut f = self.create_excl(&tmp, mode)?;
            f.write_all(data)?;
            f.sync_all()?;
            let (a, b) = (cstr(&tmp)?, cstr(name)?);
            // SAFETY: both names are NUL-terminated; the dir fd is open.
            cvt(unsafe { libc::renameat(self.fd(), a.as_ptr(), self.fd(), b.as_ptr()) })?;
            self.sync()
        };
        let r = write();
        if r.is_err() {
            let _ = self.unlink(&tmp);
        }
        ctx(r, "cannot write", &target)
    }
}

/// Checks a directory's metadata (see `Dir::secure`).
pub fn check_dir(meta: &fs::Metadata, path: &Path, private: bool) -> Result<()> {
    if !meta.file_type().is_dir() {
        return Err(err!("{} is not a directory", path.display()));
    }
    if meta.uid() != geteuid() {
        return Err(err!(
            "directory {} is owned by uid {}, not by uid {}; refusing to use it",
            path.display(),
            meta.uid(),
            geteuid()
        ));
    }
    let mode = meta.mode() & 0o7777;
    if mode & 0o022 != 0 || (private && mode & 0o077 != 0) {
        let want = if private { "0700" } else { "0710" };
        return Err(err!(
            "directory {} has mode {mode:04o}; other users must not be able to write to it{} (run: chmod {want} {})",
            path.display(),
            if private { " or read it" } else { "" },
            path.display()
        ));
    }
    Ok(())
}

/// Writes a file atomically into a verified private directory, creating it if needed.
pub fn write_file_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let (dir, name) = split_path(path)?;
    Dir::secure(&dir, true)?.write_atomic(name, data, mode)
}

pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: buf is valid for buf.len() bytes; gethostname NUL-terminates on success.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return "unknown".into();
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

pub fn isatty(fd: i32) -> bool {
    // SAFETY: isatty only inspects the descriptor.
    unsafe { libc::isatty(fd) == 1 }
}

/// Terminal state saved by `echo_off`, restored by `echo_restore` or the SIGINT handler.
static SAVED_TERMIOS: std::sync::OnceLock<libc::termios> = std::sync::OnceLock::new();

extern "C" fn restore_and_reraise(sig: libc::c_int) {
    if let Some(t) = SAVED_TERMIOS.get() {
        // SAFETY: tcsetattr, signal and raise are async-signal-safe; t is a valid termios.
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, t);
        }
    }
    // SAFETY: as above.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// Turns terminal echo off for stdin and makes Ctrl-C (and SIGTERM/SIGHUP) restore it.
/// Returns false if stdin is not a terminal.
pub fn echo_off() -> bool {
    // SAFETY: termios is plain data; tcgetattr fills it and tcsetattr reads it. The handler
    // only calls async-signal-safe functions.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(0, &mut t) != 0 {
            return false;
        }
        let _ = SAVED_TERMIOS.set(t);
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            libc::signal(sig, restore_and_reraise as *const () as libc::sighandler_t);
        }
        t.c_lflag &= !libc::ECHO;
        libc::tcsetattr(0, libc::TCSANOW, &t) == 0
    }
}

pub fn echo_restore() {
    if let Some(t) = SAVED_TERMIOS.get() {
        // SAFETY: t is a valid termios saved by echo_off.
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, t);
            for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
                libc::signal(sig, libc::SIG_DFL);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_rfc3339() {
        assert_eq!(rfc3339_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339_ms(1_369_353_600_123), "2013-05-24T00:00:00.123Z");
        assert_eq!(rfc3339_ms(951_825_600_000), "2000-02-29T12:00:00.000Z");
        for ms in [0, 1_369_353_600_123, 951_825_600_000, 1_795_000_000_999] {
            assert_eq!(parse_rfc3339_ms(&rfc3339_ms(ms)), Some(ms));
        }
        assert_eq!(parse_rfc3339_ms("2026"), None);
        assert_eq!(parse_rfc3339_ms("2026-11-17T09:08:07.12xZ"), None);
        assert_eq!(parse_rfc3339_ms("é026-11-17T09:08:07.123Z"), None);
    }

    #[test]
    fn encodes() {
        assert_eq!(hex(&[0, 0xab, 0xff]), "00abff");
        assert_eq!(unhex("00abff").unwrap(), vec![0, 0xab, 0xff]);
        assert!(unhex("0g").is_none());
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn escapes_control_characters() {
        assert_eq!(escape("plain text"), "plain text");
        assert_eq!(escape("a\nb\x1b[31mc"), "a\\nb\\u{1b}[31mc");
        assert_eq!(escape("x\u{202e}y\u{7f}"), "x\\u{202e}y\\u{7f}");
        assert_eq!(cap("abcdef", 3), "abc...");
        assert_eq!(cap("ab", 3), "ab");
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bouncer-util-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn secure_dirs_and_atomic_writes() {
        let d = tmpdir("dir");
        let dir = Dir::secure(&d.join("a/b"), true).unwrap();
        assert_eq!(fs::metadata(d.join("a/b")).unwrap().mode() & 0o777, 0o700);
        dir.write_atomic(OsStr::new("f"), b"hello", 0o600).unwrap();
        assert_eq!(fs::read(d.join("a/b/f")).unwrap(), b"hello");
        assert_eq!(fs::metadata(d.join("a/b/f")).unwrap().mode() & 0o777, 0o600);
        // No temp files are left behind.
        assert_eq!(fs::read_dir(d.join("a/b")).unwrap().count(), 1);

        // A pre-existing symlink is never followed when creating a file.
        std::os::unix::fs::symlink(d.join("victim"), d.join("a/b/link")).unwrap();
        assert!(dir.create_excl(OsStr::new("link"), 0o600).is_err());
        assert!(dir.open_at(OsStr::new("link"), libc::O_RDONLY, 0).is_err());
        assert!(!d.join("victim").exists());

        // Group/world-accessible or symlinked directories are refused.
        fs::set_permissions(d.join("a/b"), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Dir::open(&d.join("a/b"), true).is_err());
        assert!(Dir::open(&d.join("a/b"), false).is_ok());
        fs::set_permissions(d.join("a/b"), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Dir::open(&d.join("a/b"), false).is_err());
        std::os::unix::fs::symlink(d.join("a/b"), d.join("a/s")).unwrap();
        let e = Dir::open(&d.join("a/s"), false).err().unwrap().to_string();
        assert!(e.contains("symlink"), "{e}");
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn secret_file_checks() {
        let d = tmpdir("secret");
        Dir::secure(&d, true).unwrap();
        let p = d.join("k");
        fs::write(&p, "x").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_secret_file(&p, 100).is_err());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(&**read_secret_file(&p, 100).unwrap(), b"x");
        std::os::unix::fs::symlink(&p, d.join("l")).unwrap();
        assert!(read_secret_file(&d.join("l"), 100).is_err());
        fs::remove_dir_all(&d).unwrap();
    }
}
