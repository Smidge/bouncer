//! End-to-end tests: each test runs a real daemon on a private socket in a temp directory.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_bouncer");
const SECRET: &str = "fake-s3cr3t-0123456789";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Env {
    dir: PathBuf,
    daemon: Option<Child>,
}

fn private_dir() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("bnc-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

impl Env {
    /// Initialises a vault (with `config` as config.toml) without starting the daemon.
    fn init(config: &str) -> Env {
        let dir = private_dir();
        let cfg = dir.join("config.toml");
        fs::write(&cfg, config).unwrap();
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o600)).unwrap();
        let env = Env { dir, daemon: None };
        let out = env.run(&["init"], None, &[]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert!(stdout(&out).contains("without warranty"));
        env
    }

    /// Initialises and starts the daemon.
    fn start(config: &str) -> Env {
        let mut env = Env::init(config);
        env.serve(&[]);
        env
    }

    fn sock(&self) -> PathBuf {
        self.dir.join("bouncer.sock")
    }

    fn log_path(&self) -> PathBuf {
        self.dir.join("audit.jsonl")
    }

    fn spawn_daemon(&self, args: &[&str], f: impl FnOnce(&mut Command)) -> Child {
        let mut c = self.cmd();
        c.arg("serve").args(args).stdout(Stdio::null());
        c.stderr(
            fs::File::create(self.dir.join(format!(
                "daemon-{}.err",
                COUNTER.fetch_add(1, Ordering::SeqCst)
            )))
            .unwrap(),
        );
        f(&mut c);
        c.spawn().unwrap()
    }

    fn serve_with(&mut self, args: &[&str], f: impl FnOnce(&mut Command)) {
        let mut daemon = self.spawn_daemon(args, f);
        let t = Instant::now();
        while UnixStream::connect(self.sock()).is_err() {
            if let Some(status) = daemon.try_wait().unwrap() {
                panic!("daemon exited with {status}: {}", self.daemon_errors());
            }
            assert!(
                t.elapsed() < Duration::from_secs(10),
                "daemon did not start"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        self.daemon = Some(daemon);
    }

    fn serve(&mut self, args: &[&str]) {
        self.serve_with(args, |_| {});
    }

    fn stop(&mut self) {
        if let Some(mut d) = self.daemon.take() {
            let _ = d.kill();
            let _ = d.wait();
        }
    }

    fn daemon_errors(&self) -> String {
        let mut s = String::new();
        for e in fs::read_dir(&self.dir).unwrap().flatten() {
            if e.file_name().to_string_lossy().starts_with("daemon-") {
                s.push_str(&fs::read_to_string(e.path()).unwrap_or_default());
            }
        }
        s
    }

    /// Runs `serve` expecting it to fail; returns its stderr.
    fn serve_fails(&self, args: &[&str]) -> String {
        let out = self.cmd().arg("serve").args(args).output().unwrap();
        assert_ne!(out.status.code(), Some(0), "serve should have failed");
        stderr(&out)
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(BIN);
        c.env("BOUNCER_HOME", &self.dir)
            .env_remove("BOUNCER_REASON")
            .env_remove("BOUNCER_CONFIG")
            .env_remove("BOUNCER_SOCKET")
            .env_remove("BOUNCER_SERVER_UID");
        c
    }

    fn run(&self, args: &[&str], stdin: Option<&str>, envs: &[(&str, &str)]) -> Output {
        let mut c = self.cmd();
        c.args(args)
            .envs(envs.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        let mut input = child.stdin.take().unwrap();
        let _ = input.write_all(stdin.unwrap_or("").as_bytes());
        drop(input);
        child.wait_with_output().unwrap()
    }

    fn set(&self, name: &str, value: &str) {
        let out = self.run(&["set", name], Some(value), &[]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    }

    fn get(&self, name: &str) -> Output {
        self.run(
            &["get", name, "--reason", "integration test read"],
            None,
            &[],
        )
    }

    fn log_entries(&self) -> Vec<serde_json::Value> {
        fs::read_to_string(self.log_path())
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn ops(&self) -> Vec<String> {
        self.log_entries()
            .iter()
            .map(|e| e["op"].as_str().unwrap().to_string())
            .collect()
    }

    /// Sends raw bytes and returns the raw answer.
    fn raw(&self, req: &[u8]) -> String {
        let mut s = UnixStream::connect(self.sock()).unwrap();
        s.write_all(req).unwrap();
        let mut resp = String::new();
        let _ = s.read_to_string(&mut resp);
        resp
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        self.stop();
        let _ = fs::set_permissions(&self.dir, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn uid() -> u32 {
    // SAFETY: getuid cannot fail.
    unsafe { libc::getuid() }
}

#[test]
fn get_set_rm_ls_and_reason_rules() {
    let env = Env::start("audit_fsync = \"strict\"\n");
    let out = env.run(
        &[
            "set",
            "API_TOKEN",
            "--desc",
            "test token",
            "--tag",
            "work",
            "--reason",
            "rotating the token",
        ],
        Some(&format!("{SECRET}\n")),
        &[],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));

    let ls = env.run(&["ls"], None, &[]);
    assert!(
        stdout(&ls).contains("API_TOKEN  [work] test token"),
        "{}",
        stdout(&ls)
    );
    assert!(!stdout(&ls).contains(SECRET));

    // No reason: refused before contacting the daemon, with guidance.
    let out = env.run(&["get", "API_TOKEN"], None, &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("reason is required"),
        "{}",
        stderr(&out)
    );
    assert!(out.stdout.is_empty());
    let out = env.run(&["get", "API_TOKEN", "--reason", "   "], None, &[]);
    assert_eq!(out.status.code(), Some(2));

    // Too short for min_reason_len (8): denied by policy and audited.
    let out = env.run(&["get", "API_TOKEN", "--reason", "x"], None, &[]);
    assert_eq!(out.status.code(), Some(3));
    assert!(stderr(&out).contains("too short"), "{}", stderr(&out));

    let out = env.get("API_TOKEN");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        SECRET,
        "trailing newline is stripped on set and not added on get"
    );

    let out = env.run(
        &["get", "API_TOKEN", "-n"],
        None,
        &[("BOUNCER_REASON", "reason from the environment")],
    );
    assert_eq!(stdout(&out), format!("{SECRET}\n"));

    let out = env.run(
        &["get", "NOPE", "--reason=checking a missing one"],
        None,
        &[],
    );
    assert_eq!(out.status.code(), Some(4));

    // Values are never accepted from argv.
    let out = env.run(&["set", "X", "value-in-argv"], None, &[]);
    assert_eq!(out.status.code(), Some(2));

    let out = env.run(&["rm", "API_TOKEN"], None, &[]);
    assert_eq!(out.status.code(), Some(0));
    let out = env.get("API_TOKEN");
    assert_eq!(out.status.code(), Some(4));

    let entries = env.log_entries();
    let ops: Vec<(&str, &str)> = entries
        .iter()
        .filter(|e| e["op"] != "init" && e["op"] != "start")
        .map(|e| (e["op"].as_str().unwrap(), e["result"].as_str().unwrap()))
        .collect();
    assert_eq!(
        ops,
        vec![
            ("set", "ok"),
            ("ls", "ok"),
            ("get", "denied"),
            ("get", "ok"),
            ("get", "ok"),
            ("get", "not_found"),
            ("rm", "ok"),
            ("get", "not_found"),
        ]
    );
    let set = entries.iter().find(|e| e["op"] == "set").unwrap();
    assert_eq!(set["reason"], "rotating the token");
    assert!(set["txn"].is_string() && set["vault_gen"] == 2 && set["vault_hash"].is_string());
    let first_get = entries
        .iter()
        .find(|e| e["op"] == "get" && e["result"] == "ok")
        .unwrap();
    assert_eq!(first_get["reason"], "integration test read");
    assert_eq!(first_get["decision"], "allow");
    assert_eq!(first_get["policy"], "require-reason");
    assert!(first_get["peer"]["pid"].as_i64().unwrap() > 0);
    assert!(
        first_get["attribution"]["chain"][0]["exe"]
            .as_str()
            .unwrap()
            .ends_with("bouncer")
    );
    assert!(first_get["ts"].as_str().unwrap().ends_with('Z'));
    assert!(first_get["mac"].as_str().unwrap().len() == 64);
    let raw = fs::read_to_string(env.log_path()).unwrap();
    assert!(
        !raw.contains(SECRET),
        "the audit log must never contain values"
    );
    let vault = fs::read(env.dir.join("vault.bin")).unwrap();
    assert!(!vault.windows(SECRET.len()).any(|w| w == SECRET.as_bytes()));
}

#[test]
fn exec_redacts_validates_and_passes_exit_code() {
    let env = Env::start("");
    env.set("TOK", SECRET);
    env.set("work/db-pass", "fake-db-password");
    let script = r#"
        printf 'out:%s\n' "$TOK"
        printf 'err:%s\n' "$DB" >&2
        printf 'split:%s' "$(printf %s "$TOK" | cut -c1-6)"
        sleep 0.2
        printf '%s|\n' "$(printf %s "$TOK" | cut -c7-)"
        printf 'auto:%s\n' "$WORK_DB_PASS"
        exit 7
    "#;
    let out = env.run(
        &[
            "exec",
            "--reason",
            "run the deploy script",
            "TOK",
            "work/db-pass=DB",
            "work/db-pass",
            "--",
            "sh",
            "-c",
            script,
        ],
        None,
        &[],
    );
    assert_eq!(out.status.code(), Some(7), "{}", stderr(&out));
    let o = stdout(&out);
    assert!(o.contains("out:[REDACTED:1]\n"), "{o}");
    assert!(
        o.contains("split:[REDACTED:1]|\n"),
        "value split across writes: {o}"
    );
    assert!(o.contains("auto:[REDACTED:2]\n"), "{o}");
    assert!(
        stderr(&out).contains("err:[REDACTED:2]"),
        "{}",
        stderr(&out)
    );
    assert!(!o.contains(SECRET) && !stderr(&out).contains("fake-db-password"));
    assert!(!o.contains("work/db-pass"), "markers never name the secret");

    let out = env.run(&["exec", "TOK", "--", "true"], None, &[]);
    assert_eq!(out.status.code(), Some(2), "exec needs a reason too");
    // Environment variable names are validated, and collisions refused.
    let out = env.run(
        &["exec", "-r", "checking validation", "TOK=1X", "--", "true"],
        None,
        &[],
    );
    assert_eq!(out.status.code(), Some(2));
    env.set("work.db-pass", "other-value");
    let out = env.run(
        &[
            "exec",
            "-r",
            "checking validation",
            "work/db-pass",
            "work.db-pass",
            "--",
            "true",
        ],
        None,
        &[],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("WORK_DB_PASS"), "{}", stderr(&out));

    let last = env
        .log_entries()
        .into_iter()
        .rfind(|e| e["op"] == "exec")
        .unwrap();
    assert_eq!(last["names"].as_array().unwrap().len(), 3);

    // A background grandchild that keeps the pipes open does not hang exec.
    let t = Instant::now();
    let out = env.run(
        &[
            "exec",
            "-r",
            "checking the drain",
            "TOK",
            "--",
            "sh",
            "-c",
            "sleep 20 & echo started",
        ],
        None,
        &[],
    );
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains("started"));
    assert!(
        t.elapsed() < Duration::from_secs(10),
        "exec waited for a background process"
    );
}

#[test]
fn exec_forwards_signals() {
    let env = Env::start("");
    env.set("TOK", SECRET);
    let mut c = env.cmd();
    c.args([
        "exec",
        "-r",
        "signal forwarding test",
        "TOK",
        "--",
        "sh",
        "-c",
        "trap 'echo got-term; exit 9' TERM; while :; do sleep 0.1; done",
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let child = c.spawn().unwrap();
    let pid = child.id() as i32;
    std::thread::sleep(Duration::from_millis(700));
    // SAFETY: plain kill of our own child.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    let watchdog = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(10));
        // SAFETY: as above; SIGKILL if forwarding did not work, so the test fails, not hangs.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    });
    let out = child.wait_with_output().unwrap();
    drop(watchdog);
    assert_eq!(out.status.code(), Some(9), "{}", stderr(&out));
    assert!(stdout(&out).contains("got-term"));
}

#[test]
fn log_filters_escaping_and_chain_verification() {
    let env = Env::start("context_vars = [\"BOUNCER_TEST_THREAD\"]\n");
    env.set("A", "fake-a-value");
    env.set("B", "fake-b-value");
    for (name, thread) in [("A", "thread-1"), ("B", "thread-2"), ("A", "thread-2")] {
        let out = env.run(
            &["get", name, "--reason", "checking log filters"],
            None,
            &[("BOUNCER_TEST_THREAD", thread)],
        );
        assert_eq!(out.status.code(), Some(0));
    }
    let count = |args: &[&str]| {
        let mut a = vec!["log", "--json"];
        a.extend_from_slice(args);
        stdout(&env.run(&a, None, &[])).lines().count()
    };
    assert_eq!(count(&["--name", "A"]), 3);
    assert_eq!(count(&["--thread", "thread-2"]), 2);
    assert_eq!(count(&["--thread", "thread-2", "--name", "B"]), 1);
    assert_eq!(count(&["--tail", "2"]), 2);
    assert_eq!(count(&["--since", "2999-01-01"]), 0);
    assert_eq!(count(&["--since", "1h"]), count(&[]));
    let out = env.run(&["log", "--since", "99999999999999999999d"], None, &[]);
    assert_ne!(
        out.status.code(),
        Some(0),
        "overflowing --since is an error"
    );
    let human = stdout(&env.run(&["log", "--tail", "1"], None, &[]));
    assert!(human.contains("BOUNCER_TEST_THREAD=thread-2"), "{human}");
    assert!(human.contains("reason: checking log filters"), "{human}");

    // Control characters in stored text are escaped on display (but stored raw).
    let out = env.run(
        &["set", "C", "--desc", "evil\x1b[2J\nFAKE LINE"],
        Some("v-c-value"),
        &[],
    );
    assert_eq!(out.status.code(), Some(0));
    let ls = stdout(&env.run(&["ls"], None, &[]));
    assert!(
        !ls.contains('\x1b') && ls.contains("evil\\u{1b}[2J\\nFAKE LINE"),
        "{ls}"
    );
    let out = env.run(
        &[
            "get",
            "C",
            "--reason",
            "looks fine\n2026-01-01 #1 get ok FAKE\x1b[31m",
        ],
        None,
        &[],
    );
    assert_eq!(out.status.code(), Some(0));
    let human = stdout(&env.run(&["log", "--tail", "1"], None, &[]));
    assert!(!human.contains('\x1b'), "{human:?}");
    assert_eq!(human.lines().count(), 2, "{human}");
    assert!(
        env.log_entries().last().unwrap()["reason"]
            .as_str()
            .unwrap()
            .contains('\x1b')
    );

    let ok = env.run(&["verify-log"], None, &[]);
    assert_eq!(ok.status.code(), Some(0), "{}", stderr(&ok));
    assert!(stdout(&ok).starts_with("ok: "));
    assert!(!stdout(&ok).contains("structure only"));
    let ok = env.run(&["verify-log", "--daemon"], None, &[]);
    assert_eq!(ok.status.code(), Some(0), "{}", stderr(&ok));

    // Anchor the head, add entries, and check the anchor is still in the log.
    let st = stdout(&env.run(&["status", "--json"], None, &[]));
    let st: serde_json::Value = serde_json::from_str(&st).unwrap();
    let head = st["audit"]["head"].as_str().unwrap().to_string();
    env.get("A");
    let ok = env.run(&["verify-log", "--expect-head", &head], None, &[]);
    assert_eq!(ok.status.code(), Some(0), "{}", stderr(&ok));

    // Truncating the tail is caught against the anchor.
    let text = fs::read_to_string(env.log_path()).unwrap();
    let anchored_seq: usize = head.split(':').next().unwrap().parse().unwrap();
    let kept: String = text
        .lines()
        .take(anchored_seq - 1)
        .map(|l| format!("{l}\n"))
        .collect();
    let orig = text.clone();
    fs::write(env.log_path(), &kept).unwrap();
    let bad = env.run(&["verify-log", "--expect-head", &head], None, &[]);
    assert_eq!(bad.status.code(), Some(8));
    assert!(
        stderr(&bad).contains("removed from the end"),
        "{}",
        stderr(&bad)
    );
    fs::write(env.log_path(), &orig).unwrap();

    // Editing an entry breaks its MAC.
    fs::write(env.log_path(), orig.replacen("thread-1", "thread-9", 1)).unwrap();
    let bad = env.run(&["verify-log"], None, &[]);
    assert_eq!(bad.status.code(), Some(8));
    assert!(stderr(&bad).contains("MAC"), "{}", stderr(&bad));
}

#[test]
fn context_vars_from_the_oldest_ancestor_and_no_stale_cache() {
    let env = Env::start("context_vars = [\"BOUNCER_TEST_THREAD\"]\nmax_chain_depth = 2\n");
    env.set("A", "fake-a-value");
    // `bouncer exec` starts with the real thread id; deeper descendants try to override it,
    // deeper than max_chain_depth so the old depth-limited walk would have missed the root.
    let script = format!(
        "BOUNCER_TEST_THREAD=spoofed sh -c \"sh -c \\\"'{BIN}' get A --reason 'spoof attempt check' >/dev/null\\\"\""
    );
    let mut c = env.cmd();
    c.args([
        "exec",
        "--reason",
        "outer process for attribution",
        "A",
        "--",
    ])
    .args(["sh", "-c", &script])
    .env("BOUNCER_TEST_THREAD", "real-thread");
    let outer = c.spawn().unwrap();
    let outer_pid = outer.id() as i64;
    assert_eq!(outer.wait_with_output().unwrap().status.code(), Some(0));
    let e = env.log_entries().pop().unwrap();
    assert_eq!(e["op"], "get");
    let ctx = &e["attribution"]["context"]["BOUNCER_TEST_THREAD"];
    assert_eq!(ctx["value"], "real-thread", "{e}");
    assert_eq!(ctx["pid"].as_i64().unwrap(), outer_pid);
    assert_eq!(ctx["other"][0]["value"], "spoofed", "{e}");
    assert_eq!(
        e["attribution"]["chain"].as_array().unwrap().len(),
        2,
        "only max_chain_depth recorded"
    );
    assert!(e["attribution"]["ancestors"].as_u64().unwrap() > 4);
    assert_ne!(e["attribution"]["status"], "unavailable");
    assert!(e["attribution"]["cwd"].as_str().is_some());

    // The same shell process asks twice, exec'ing in between with a new environment and
    // binary (same pid, same start time): the second request must see the new state.
    let script = format!(
        "'{BIN}' get A --reason 'before the exec here' >/dev/null; exec env BOUNCER_TEST_THREAD=after-exec sh -c \"'{BIN}' get A --reason 'after the exec here' >/dev/null\""
    );
    let mut c = env.cmd();
    c.args([
        "exec",
        "--reason",
        "outer for the exec test",
        "A",
        "--",
        "sh",
        "-c",
        &script,
    ])
    .env("BOUNCER_TEST_THREAD", "before-exec");
    assert_eq!(c.output().unwrap().status.code(), Some(0));
    let entries = env.log_entries();
    let before = entries
        .iter()
        .find(|e| e["reason"] == "before the exec here")
        .unwrap();
    let after = entries
        .iter()
        .find(|e| e["reason"] == "after the exec here")
        .unwrap();
    let parent = |e: &serde_json::Value| e["attribution"]["chain"][1].clone();
    assert_eq!(
        parent(before)["pid"],
        parent(after)["pid"],
        "same parent pid"
    );
    assert!(
        parent(after)["argv"]
            .as_str()
            .unwrap()
            .contains("after the exec"),
        "{after}"
    );
    let ctx = &after["attribution"]["context"]["BOUNCER_TEST_THREAD"];
    assert_eq!(ctx["value"], "before-exec");
    assert!(
        ctx["other"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["value"] == "after-exec"),
        "{after}"
    );
}

#[test]
fn concurrent_gets() {
    let env = Env::start("");
    env.set("A", "fake-a-value");
    let sock = env.sock();
    let before = env.log_entries().len();
    let threads: Vec<_> = (0..16)
        .map(|_| {
            let sock = sock.clone();
            std::thread::spawn(move || {
                for _ in 0..25 {
                    let mut s = UnixStream::connect(&sock).unwrap();
                    s.write_all(
                        b"{\"op\":\"get\",\"names\":[\"A\"],\"reason\":\"concurrency test\"}\n",
                    )
                    .unwrap();
                    let mut resp = String::new();
                    s.read_to_string(&mut resp).unwrap();
                    assert!(resp.contains("fake-a-value"), "{resp}");
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(env.log_entries().len(), before + 16 * 25);
    let ok = env.run(&["verify-log"], None, &[]);
    assert_eq!(ok.status.code(), Some(0), "{}", stderr(&ok));
}

#[test]
fn malformed_oversized_and_unterminated_requests() {
    let env = Env::start("");
    let resp = env.raw(b"{\"op\":\"set\",\"names\":[\"A\"],\"value\":12345678901}\n");
    assert!(resp.contains("malformed request"), "{resp}");
    assert!(!resp.contains("12345678901"));
    let mut big = b"{\"op\":\"get\",\"reason\":\"".to_vec();
    big.extend(std::iter::repeat_n(b'x', 70 * 1024));
    big.extend_from_slice(b"\"}\n");
    let resp = env.raw(&big);
    assert!(resp.contains("larger than 65536"), "{resp}");
    let mut s = UnixStream::connect(env.sock()).unwrap();
    s.write_all(b"{\"op\":\"ls\"").unwrap();
    s.shutdown(std::net::Shutdown::Write).unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    assert!(resp.contains("not newline-terminated"), "{resp}");
}

#[test]
fn connection_cap_and_whole_request_deadline() {
    let env = Env::start("max_connections = 2\nrequest_timeout_ms = 2000\n");
    // Let the start-up probe connection finish first.
    std::thread::sleep(Duration::from_millis(300));
    let idle1 = UnixStream::connect(env.sock()).unwrap();
    let idle2 = UnixStream::connect(env.sock()).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let t = Instant::now();
    let resp = env.raw(b"{\"op\":\"ls\"}\n");
    assert!(resp.contains("busy"), "{resp}");
    assert!(t.elapsed() < Duration::from_millis(500));
    drop((idle1, idle2));

    // Slowloris: a byte every 150 ms never completes a line; the deadline covers the whole
    // request, not each read.
    std::thread::sleep(Duration::from_millis(2100));
    let mut s = UnixStream::connect(env.sock()).unwrap();
    let t = Instant::now();
    let mut closed = false;
    for _ in 0..40 {
        if s.write_all(b" ").is_err() {
            closed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(150));
        if t.elapsed() > Duration::from_secs(5) {
            break;
        }
    }
    let mut resp = String::new();
    let _ = s.read_to_string(&mut resp);
    assert!(closed || resp.contains("not received in time"), "{resp}");
    assert!(
        t.elapsed() < Duration::from_secs(5),
        "deadline not enforced: {:?}",
        t.elapsed()
    );
}

#[test]
fn other_uids_are_closed_before_reading_and_aggregated() {
    let other = uid() + 1;
    let env = Env::start(&format!(
        "allowed_uids = [{other}]\nadmin_uids = [{other}]\n"
    ));
    // Nothing is sent, yet the answer arrives at once: the daemon did not wait to read.
    for _ in 0..5 {
        let mut s = UnixStream::connect(env.sock()).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut resp = String::new();
        let t = Instant::now();
        let _ = s.read_to_string(&mut resp);
        assert!(resp.contains("may not use this daemon"), "{resp}");
        assert!(t.elapsed() < Duration::from_secs(1));
    }
    let out = env.get("A");
    assert_eq!(out.status.code(), Some(3));
    std::thread::sleep(Duration::from_millis(100));
    let rejects: Vec<_> = env
        .log_entries()
        .into_iter()
        .filter(|e| e["op"] == "reject")
        .collect();
    assert_eq!(
        rejects.len(),
        1,
        "one aggregated entry per minute, not one per connection"
    );
    assert_eq!(rejects[0]["uids"][0], uid());
}

#[test]
fn refuses_untrusted_socket_paths_and_wrong_server_uid() {
    let mut env = Env::init("");
    // A non-socket at the socket path is never removed.
    fs::write(env.sock(), "important").unwrap();
    let e = env.serve_fails(&[]);
    assert!(e.contains("not a socket"), "{e}");
    assert_eq!(fs::read_to_string(env.sock()).unwrap(), "important");
    fs::remove_file(env.sock()).unwrap();
    // Nor is a symlink.
    std::os::unix::fs::symlink(env.dir.join("vault.bin"), env.sock()).unwrap();
    let e = env.serve_fails(&[]);
    assert!(e.contains("not a socket"), "{e}");
    assert!(env.dir.join("vault.bin").exists());
    fs::remove_file(env.sock()).unwrap();
    // A socket directory others can write to is refused.
    let sockdir = env.dir.join("run");
    fs::create_dir(&sockdir).unwrap();
    fs::set_permissions(&sockdir, fs::Permissions::from_mode(0o777)).unwrap();
    let out = env
        .cmd()
        .args([
            "--socket",
            sockdir.join("b.sock").to_str().unwrap(),
            "serve",
        ])
        .output()
        .unwrap();
    assert!(
        stderr(&out).contains("other users must not be able to write"),
        "{}",
        stderr(&out)
    );
    // A data directory others can read is refused.
    fs::set_permissions(&env.dir, fs::Permissions::from_mode(0o755)).unwrap();
    let e = env.serve_fails(&[]);
    assert!(e.contains("0755"), "{e}");
    fs::set_permissions(&env.dir, fs::Permissions::from_mode(0o700)).unwrap();

    env.serve(&[]);
    env.set("A", "fake-a-value");
    // The client refuses a daemon that does not run as the expected uid, before sending.
    let out = env.run(
        &["get", "A", "--reason", "server identity check"],
        None,
        &[("BOUNCER_SERVER_UID", "12345")],
    );
    assert_eq!(out.status.code(), Some(6), "{}", stderr(&out));
    assert!(stderr(&out).contains("not the expected uid 12345"));
    let set = env.run(
        &["set", "B"],
        Some("would-leak"),
        &[("BOUNCER_SERVER_UID", "12345")],
    );
    assert_eq!(set.status.code(), Some(6));
    assert!(
        !env.log_entries()
            .iter()
            .any(|e| e["reason"] == "server identity check")
    );
}

#[test]
fn store_lock_and_key_checks() {
    let mut env = Env::start("");
    // A second daemon on the same store (different socket) fails clearly.
    let out = env
        .cmd()
        .args([
            "--socket",
            env.dir.join("second.sock").to_str().unwrap(),
            "serve",
        ])
        .output()
        .unwrap();
    assert!(
        stderr(&out).contains("another bouncer process"),
        "{}",
        stderr(&out)
    );
    let out = env.run(&["init"], None, &[]);
    assert_ne!(out.status.code(), Some(0));
    env.stop();

    let key = env.dir.join("key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    let e = env.serve_fails(&[]);
    assert!(e.contains("must be 0600 or 0400"), "{e}");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o400)).unwrap();
    // A symlinked key is refused.
    fs::rename(&key, env.dir.join("real-key")).unwrap();
    std::os::unix::fs::symlink(env.dir.join("real-key"), &key).unwrap();
    let e = env.serve_fails(&[]);
    assert!(e.contains("key"), "{e}");
    fs::remove_file(&key).unwrap();
    fs::rename(env.dir.join("real-key"), &key).unwrap();
    // A vault readable by others is refused.
    let vault = env.dir.join("vault.bin");
    fs::set_permissions(&vault, fs::Permissions::from_mode(0o644)).unwrap();
    let e = env.serve_fails(&[]);
    assert!(e.contains("vault.bin"), "{e}");
    fs::set_permissions(&vault, fs::Permissions::from_mode(0o600)).unwrap();
    env.serve(&[]);
}

#[test]
fn audit_failure_fails_closed_until_repaired() {
    let mut env = Env::init("audit_fsync = \"strict\"\n");
    let limit = fs::metadata(env.log_path()).unwrap().len() + 16_000;
    // A file size limit makes audit appends fail with EFBIG once the log reaches it.
    env.serve_with(&[], move |c| {
        // SAFETY: setrlimit is async-signal-safe.
        unsafe {
            c.pre_exec(move || {
                let r = libc::rlimit {
                    rlim_cur: limit,
                    rlim_max: limit,
                };
                libc::setrlimit(libc::RLIMIT_FSIZE, &r);
                Ok(())
            });
        }
    });
    env.set("A", "fake-a-value");
    let mut codes = Vec::new();
    for _ in 0..60 {
        let out = env.get("A");
        let code = out.status.code().unwrap();
        if code == 0 {
            assert_eq!(stdout(&out), "fake-a-value");
        } else {
            assert!(out.stdout.is_empty(), "nothing released after the failure");
        }
        codes.push(code);
        if code == 7 {
            break;
        }
    }
    assert_eq!(codes.first(), Some(&0));
    assert_eq!(codes.last(), Some(&7), "{codes:?}");
    // Latched: later requests (and changes) are refused too.
    assert_eq!(env.get("A").status.code(), Some(7));
    assert_eq!(
        env.run(&["set", "B"], Some("x-value"), &[]).status.code(),
        Some(7)
    );
    // The log still ends with a complete entry and verifies.
    assert!(fs::read(env.log_path()).unwrap().ends_with(b"\n"));
    let ok = env.run(&["verify-log"], None, &[]);
    assert_eq!(ok.status.code(), Some(0), "{}", stderr(&ok));
    env.stop();
    // Restarting is not enough...
    let e = env.serve_fails(&[]);
    assert!(e.contains("bouncer repair"), "{e}");
    // ...until repair.
    let out = env.run(&["repair"], None, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    env.serve(&[]);
    assert_eq!(env.get("A").status.code(), Some(0));
}

#[test]
fn mutations_are_audited_before_commit_and_rolled_back() {
    let mut env = Env::start("");
    env.set("A", "old-value-1");
    // Make the vault directory read-only so saving fails (the log fd stays writable).
    fs::set_permissions(&env.dir, fs::Permissions::from_mode(0o500)).unwrap();
    let out = env.run(&["set", "A"], Some("new-value-2"), &[]);
    fs::set_permissions(&env.dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("rolled back"), "{}", stderr(&out));
    assert_eq!(
        stdout(&env.get("A")),
        "old-value-1",
        "the failed change is not visible"
    );
    let entries = env.log_entries();
    let n = entries.len();
    let (set, abort) = (&entries[n - 3], &entries[n - 2]);
    assert_eq!(set["op"], "set");
    assert_eq!(abort["op"], "abort");
    assert_eq!(set["txn"], abort["txn"]);
    // The daemon restarts cleanly: the log knows the change was aborted.
    env.stop();
    env.serve(&[]);
    assert_eq!(stdout(&env.get("A")), "old-value-1");
}

#[test]
fn vault_rollback_is_detected() {
    let mut env = Env::start("");
    env.set("A", "value-one");
    let snapshot = fs::read(env.dir.join("vault.bin")).unwrap();
    env.set("A", "value-two");
    env.stop();
    fs::write(env.dir.join("vault.bin"), &snapshot).unwrap();
    let e = env.serve_fails(&[]);
    assert!(e.contains("does not match the audit log"), "{e}");
    // The override works and is itself audited.
    env.serve(&["--accept-vault-mismatch"]);
    assert_eq!(stdout(&env.get("A")), "value-one");
    assert!(env.ops().contains(&"accept_vault_mismatch".to_string()));
    env.stop();
    env.serve(&[]);

    // An emptied log is also caught.
    env.stop();
    fs::write(env.log_path(), "").unwrap();
    let e = env.serve_fails(&[]);
    assert!(e.contains("does not match"), "{e}");
}

#[test]
fn write_reason_and_admin_separation() {
    let mut env = Env::start("require_write_reason = true\n");
    let out = env.run(&["set", "A"], Some("fake-a-value"), &[]);
    assert_eq!(out.status.code(), Some(2));
    let out = env.run(
        &["set", "A", "--reason", "adding a test secret"],
        Some("fake-a-value"),
        &[],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    env.stop();

    let admin = env.dir.join("admin.sock");
    fs::write(
        env.dir.join("config.toml"),
        format!("admin_socket = \"{}\"\n", admin.display()),
    )
    .unwrap();
    env.serve(&[]);
    let out = env.run(&["set", "B"], Some("fake-b-value"), &[]);
    assert_eq!(out.status.code(), Some(3));
    assert!(stderr(&out).contains("admin socket"), "{}", stderr(&out));
    let out = env.run(
        &["--socket", admin.to_str().unwrap(), "set", "B"],
        Some("fake-b-value"),
        &[],
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(
        std::fs::metadata(&admin).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn doctor_reports_problems() {
    let env = Env::start("");
    let out = env.run(&["doctor"], None, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    assert!(stdout(&out).contains("same-user mode"), "{}", stdout(&out));
    fs::set_permissions(
        env.dir.join("audit.jsonl"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let out = env.run(&["doctor"], None, &[]);
    assert_eq!(out.status.code(), Some(8), "{}", stdout(&out));
    assert!(stdout(&out).contains("FAIL"));
}

#[test]
fn migrates_a_version_1_log() {
    let mut env = Env::init("");
    // Write a v1 log (unkeyed SHA-256 chain).
    let mut prev = "0".repeat(64);
    let mut text = String::new();
    for seq in 1..=2 {
        let line = format!(
            "{{\"ts\":\"2026-01-01T00:00:00.000Z\",\"seq\":{seq},\"op\":\"get\",\"prev\":\"{prev}\"}}"
        );
        prev = bouncer::util::sha256_hex(line.as_bytes());
        text.push_str(&line);
        text.push('\n');
    }
    fs::write(env.log_path(), &text).unwrap();
    let e = env.serve_fails(&[]);
    assert!(e.contains("migrate-log"), "{e}");
    let out = env.run(&["migrate-log"], None, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stdout(&out).contains("2 entries"));
    env.serve(&[]);
    let first = &env.log_entries()[0];
    assert_eq!(first["op"], "init");
    assert!(first["note"].as_str().unwrap().contains(&prev));
}

#[cfg(feature = "net")]
mod http {
    use super::*;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone)]
    pub struct Req {
        pub path: String,
        pub headers: HashMap<String, String>,
        pub body: Vec<u8>,
    }

    type Handler = Arc<dyn Fn(&Req) -> (u16, String) + Send + Sync>;

    /// A minimal HTTP/1.1 server that records requests.
    pub fn serve(handler: Handler) -> (u16, Arc<Mutex<Vec<Req>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { continue };
                let (seen, handler) = (seen2.clone(), handler.clone());
                std::thread::spawn(move || {
                    let mut w = conn.try_clone().unwrap();
                    let mut r = BufReader::new(conn);
                    loop {
                        let mut line = String::new();
                        if r.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
                        let mut headers = HashMap::new();
                        loop {
                            let mut h = String::new();
                            r.read_line(&mut h).unwrap();
                            let h = h.trim_end();
                            if h.is_empty() {
                                break;
                            }
                            let (k, v) = h.split_once(':').unwrap();
                            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
                        }
                        let len: usize = headers
                            .get("content-length")
                            .and_then(|l| l.parse().ok())
                            .unwrap_or(0);
                        let mut body = vec![0; len];
                        r.read_exact(&mut body).unwrap();
                        let req = Req {
                            path,
                            headers,
                            body,
                        };
                        let (status, text) = handler(&req);
                        seen.lock().unwrap().push(req);
                        let resp = format!(
                            "HTTP/1.1 {status} X\r\nContent-Length: {}\r\n\r\n{text}",
                            text.len()
                        );
                        w.write_all(resp.as_bytes()).unwrap();
                    }
                });
            }
        });
        (port, seen)
    }

    fn secret_file(dir: &Path, name: &str, value: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, value).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        p
    }

    fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
        let t = Instant::now();
        while !f() {
            assert!(
                t.elapsed() < Duration::from_secs(15),
                "timed out waiting for {what}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn sinks_upload_resume_and_mirror() {
        // Like S3 with If-None-Match: an existing key answers 412.
        let keys = Arc::new(Mutex::new(std::collections::HashSet::new()));
        let (port, seen) = serve(Arc::new(move |r| {
            if keys.lock().unwrap().insert(r.path.clone()) {
                (200, String::new())
            } else {
                (412, String::new())
            }
        }));
        let dir = private_dir();
        let ak = secret_file(&dir, "ak", "AKIDEXAMPLE\n");
        let sk = secret_file(&dir, "sk", "fake-s3-secret-for-tests");
        let mirror = dir.join("mirror/audit.jsonl");
        let config = format!(
            r#"
[[sink]]
type = "s3"
endpoint = "http://127.0.0.1:{port}"
allow_insecure_http = true
bucket = "audit-bucket"
prefix = "test/prefix"
access_key_id_file = "{}"
secret_access_key_file = "{}"

[[sink]]
type = "file"
path = "{}"
"#,
            ak.display(),
            sk.display(),
            mirror.display()
        );
        let mut env = Env::start(&config);
        env.set("A", "fake-a-value");
        assert_eq!(env.get("A").status.code(), Some(0));
        let log_len = |env: &Env| env.log_entries().len();
        wait_for("uploads", || seen.lock().unwrap().len() >= log_len(&env));
        wait_for("mirror", || {
            fs::read(&mirror).ok() == fs::read(env.log_path()).ok()
        });

        let reqs = seen.lock().unwrap().clone();
        let lines: Vec<String> = fs::read_to_string(env.log_path())
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        let host = bouncer::util::hostname();
        for (i, r) in reqs.iter().enumerate() {
            let entry: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
            assert_eq!(std::str::from_utf8(&r.body).unwrap(), lines[i]);
            let key = bouncer::sink::s3::object_key(
                "test/prefix",
                &host,
                entry["ts"].as_str().unwrap(),
                entry["log_id"].as_str().unwrap(),
                entry["seq"].as_u64().unwrap(),
            );
            assert_eq!(
                r.path,
                format!(
                    "/audit-bucket/{}",
                    bouncer::sink::s3::uri_encode(&key, true)
                )
            );
            assert_eq!(r.headers["if-none-match"], "*");
            assert!(r.headers["authorization"].contains("Credential=AKIDEXAMPLE/"));
        }
        // The cursor is bound to the log and destination.
        let cursor: serde_json::Value =
            serde_json::from_slice(&fs::read(env.dir.join("audit.jsonl.s3.cursor")).unwrap())
                .unwrap();
        assert_eq!(
            cursor["log_id"],
            lines[0].split("\"log_id\":\"").nth(1).unwrap()[..32]
        );
        assert!(
            cursor["dest"]
                .as_str()
                .unwrap()
                .starts_with("s3:http://127.0.0.1")
        );

        // Crash and resume: everything after the saved cursor is sent once more at most, and
        // an object that already exists is never replaced (412 counts as delivered).
        let cursor_path = env.dir.join("audit.jsonl.s3.cursor");
        let last_seq = env.log_entries().last().unwrap()["seq"].as_u64().unwrap();
        wait_for("cursor", || {
            fs::read(&cursor_path)
                .ok()
                .and_then(|c| serde_json::from_slice::<serde_json::Value>(&c).ok())
                .is_some_and(|c| c["seq"].as_u64() == Some(last_seq))
        });
        env.stop();
        let before = seen.lock().unwrap().len();
        env.serve(&[]);
        env.get("A");
        let distinct = || {
            let mut p: Vec<String> = seen
                .lock()
                .unwrap()
                .iter()
                .map(|r| r.path.clone())
                .collect();
            p.sort();
            p.dedup();
            p.len()
        };
        wait_for("resume", || distinct() >= log_len(&env));
        let total = seen.lock().unwrap().len();
        assert_eq!(total, distinct(), "an entry was uploaded twice");
        assert!(seen.lock().unwrap().len() > before);
        wait_for("mirror after restart", || {
            fs::read(&mirror).ok() == fs::read(env.log_path()).ok()
        });
        let st: serde_json::Value =
            serde_json::from_str(&stdout(&env.run(&["status", "--json"], None, &[]))).unwrap();
        assert_eq!(st["sinks"].as_array().unwrap().len(), 2);
        assert!(st["sinks"][0]["last_success"].is_string());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn admission_model_decides_and_is_audited() {
        let (port, seen) = serve(Arc::new(|r| {
            let body = String::from_utf8_lossy(&r.body);
            let d = if body.contains("deny-me-please") {
                "deny"
            } else {
                "allow"
            };
            let text = format!("{{\"decision\":\"{d}\",\"reasoning\":\"model says {d}\"}}");
            (200, serde_json::json!({"content": [{"type": "text", "text": text}], "stop_reason": "end_turn"}).to_string())
        }));
        let dir = private_dir();
        let key = secret_file(&dir, "llm", "fake-llm-key");
        let config = format!(
            "[admission]\nenabled = true\nprovider = \"anthropic\"\nendpoint = \"http://127.0.0.1:{port}/v1/messages\"\nallow_insecure_http = true\nmodel = \"test-model\"\napi_key_file = \"{}\"\n",
            key.display()
        );
        let env = Env::start(&config);
        env.set("A", "fake-a-value");
        let out = env.run(&["get", "A", "--reason", "deploy the docs site"], None, &[]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert!(
            stderr(&out).contains("admission: model says allow"),
            "{}",
            stderr(&out)
        );
        let out = env.run(&["get", "A", "--reason", "deny-me-please now"], None, &[]);
        assert_eq!(out.status.code(), Some(3));
        assert!(out.stdout.is_empty());
        assert!(stderr(&out).contains("model says deny"));
        let e = env.log_entries().pop().unwrap();
        assert_eq!(e["policy"], "admission");
        assert_eq!(e["admission"]["decision"], "deny");
        assert_eq!(e["admission"]["reasoning"], "model says deny");
        assert_eq!(seen.lock().unwrap().len(), 2);
        // admission/never skips the model.
        let out = env.run(
            &["set", "B", "--tag", "admission/never"],
            Some("fake-b-value"),
            &[],
        );
        assert_eq!(out.status.code(), Some(0));
        assert_eq!(
            env.run(&["get", "B", "--reason", "deny-me-please now"], None, &[])
                .status
                .code(),
            Some(0)
        );
        assert_eq!(seen.lock().unwrap().len(), 2);
        let _ = fs::remove_dir_all(&dir);
    }
}
