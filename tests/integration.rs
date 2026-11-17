//! End-to-end tests: each test runs a real daemon on a private socket in a temp directory.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
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

impl Env {
    /// Initialises a vault (with `config` as config.toml) and starts the daemon.
    fn start(config: &str) -> Env {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("bnc-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("config.toml"), config).unwrap();
        let mut env = Env { dir, daemon: None };
        let out = env.run(&["init"], None, &[]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        let daemon = env
            .cmd()
            .arg("serve")
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        env.daemon = Some(daemon);
        let sock = env.dir.join("bouncer.sock");
        let t = Instant::now();
        while UnixStream::connect(&sock).is_err() {
            assert!(
                t.elapsed() < Duration::from_secs(10),
                "daemon did not start"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        env
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(BIN);
        c.env("BOUNCER_HOME", &self.dir)
            .env_remove("BOUNCER_REASON")
            .env_remove("BOUNCER_CONFIG")
            .env_remove("BOUNCER_SOCKET");
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
        input.write_all(stdin.unwrap_or("").as_bytes()).unwrap();
        drop(input);
        child.wait_with_output().unwrap()
    }

    fn set(&self, name: &str, value: &str) {
        let out = self.run(&["set", name], Some(value), &[]);
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    }

    fn log_entries(&self) -> Vec<serde_json::Value> {
        fs::read_to_string(self.dir.join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        if let Some(mut d) = self.daemon.take() {
            let _ = d.kill();
            let _ = d.wait();
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn get_set_rm_ls_and_reason_rules() {
    let env = Env::start("audit_fsync = \"strict\"\n");
    let out = env.run(
        &["set", "API_TOKEN", "--desc", "test token", "--tag", "work"],
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

    let out = env.run(
        &["get", "API_TOKEN", "--reason", "integration test read"],
        None,
        &[],
    );
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
    let out = env.run(
        &["get", "API_TOKEN", "--reason", "after removal"],
        None,
        &[],
    );
    assert_eq!(out.status.code(), Some(4));

    let entries = env.log_entries();
    let ops: Vec<(&str, &str)> = entries
        .iter()
        .map(|e| (e["op"].as_str().unwrap(), e["result"].as_str().unwrap()))
        .collect();
    assert_eq!(
        ops,
        vec![
            ("set", "ok"),
            ("get", "denied"),
            ("get", "ok"),
            ("get", "ok"),
            ("get", "not_found"),
            ("rm", "ok"),
            ("get", "not_found"),
        ]
    );
    let first_get = &entries[2];
    assert_eq!(first_get["reason"], "integration test read");
    assert_eq!(first_get["decision"], "allow");
    assert_eq!(first_get["policy"], "require-reason");
    assert!(first_get["peer"]["pid"].as_i64().unwrap() > 0);
    assert!(
        first_get["chain"][0]["exe"]
            .as_str()
            .unwrap()
            .ends_with("bouncer")
    );
    assert!(first_get["ts"].as_str().unwrap().ends_with('Z'));
    assert_eq!(entries[1]["decision"], "deny");
    let raw = fs::read_to_string(env.dir.join("audit.jsonl")).unwrap();
    assert!(
        !raw.contains(SECRET),
        "the audit log must never contain values"
    );
}

#[test]
fn exec_redacts_and_passes_exit_code() {
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
    assert!(o.contains("out:[REDACTED:TOK]\n"), "{o}");
    assert!(
        o.contains("split:[REDACTED:TOK]|\n"),
        "value split across writes: {o}"
    );
    assert!(o.contains("auto:[REDACTED:work/db-pass]\n"), "{o}");
    assert!(
        stderr(&out).contains("err:[REDACTED:work/db-pass]"),
        "{}",
        stderr(&out)
    );
    assert!(!o.contains(SECRET) && !stderr(&out).contains("fake-db-password"));

    let out = env.run(&["exec", "TOK", "--", "true"], None, &[]);
    assert_eq!(out.status.code(), Some(2), "exec needs a reason too");

    let last = env.log_entries().pop().unwrap();
    assert_eq!(last["op"], "exec");
    assert_eq!(last["names"].as_array().unwrap().len(), 3);
}

#[test]
fn log_filters_and_chain_verification() {
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
    assert_eq!(count(&[]), 5);
    assert_eq!(count(&["--name", "A"]), 3);
    assert_eq!(count(&["--thread", "thread-2"]), 2);
    assert_eq!(count(&["--thread", "thread-2", "--name", "B"]), 1);
    assert_eq!(count(&["--tail", "2"]), 2);
    assert_eq!(count(&["--since", "1h"]), 5);
    assert_eq!(count(&["--since", "2999-01-01"]), 0);
    let human = stdout(&env.run(&["log", "--tail", "1"], None, &[]));
    assert!(human.contains("BOUNCER_TEST_THREAD=thread-2"), "{human}");
    assert!(human.contains("reason: checking log filters"), "{human}");

    let ok = env.run(&["verify-log"], None, &[]);
    assert_eq!(ok.status.code(), Some(0), "{}", stderr(&ok));
    assert!(stdout(&ok).starts_with("ok: 5 entries"));

    let path = env.dir.join("audit.jsonl");
    let text = fs::read_to_string(&path).unwrap();
    fs::write(&path, text.replacen("thread-1", "thread-9", 1)).unwrap();
    let bad = env.run(&["verify-log"], None, &[]);
    assert_eq!(bad.status.code(), Some(1));
    assert!(
        stderr(&bad).contains("hash chain broken"),
        "{}",
        stderr(&bad)
    );
}

#[test]
fn context_vars_come_from_the_oldest_ancestor() {
    let env = Env::start("context_vars = [\"BOUNCER_TEST_THREAD\"]\n");
    env.set("A", "fake-a-value");
    // `bouncer exec` starts with the real thread id; a grandchild tries to override it.
    let script = format!(
        "BOUNCER_TEST_THREAD=spoofed '{BIN}' get A --reason 'spoof attempt check' >/dev/null; s=$?; exit $s"
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
    let status = outer.wait_with_output().unwrap().status;
    assert_eq!(status.code(), Some(0));
    let e = env.log_entries().pop().unwrap();
    assert_eq!(e["op"], "get");
    let ctx = &e["context"]["BOUNCER_TEST_THREAD"];
    assert_eq!(ctx["value"], "real-thread", "{e}");
    assert_eq!(ctx["pid"].as_i64().unwrap(), outer_pid);
    assert_eq!(e["chain"][2]["pid"].as_i64().unwrap(), outer_pid);
    assert_ne!(e["attribution"], "unavailable");
    assert!(e["cwd"].as_str().is_some());
}

#[test]
fn concurrent_gets() {
    let env = Env::start("");
    env.set("A", "fake-a-value");
    let sock = env.dir.join("bouncer.sock");
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
    assert_eq!(env.log_entries().len(), 1 + 16 * 25);
    let ok = env.run(&["verify-log"], None, &[]);
    assert_eq!(ok.status.code(), Some(0), "{}", stderr(&ok));
}

#[test]
fn malformed_requests_do_not_echo_input() {
    let env = Env::start("");
    let mut s = UnixStream::connect(env.dir.join("bouncer.sock")).unwrap();
    s.write_all(b"{\"op\":\"set\",\"names\":[\"A\"],\"value\":12345678901}\n")
        .unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).unwrap();
    assert!(resp.contains("malformed request"), "{resp}");
    assert!(!resp.contains("12345678901"));
}

#[cfg(feature = "s3")]
mod s3 {
    use super::*;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone)]
    struct Req {
        method: String,
        path: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    }

    /// A minimal HTTP/1.1 server that records requests and answers 200.
    fn fake_s3() -> (u16, Arc<Mutex<Vec<Req>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(conn) = conn else { continue };
                let seen = seen2.clone();
                std::thread::spawn(move || {
                    let mut w = conn.try_clone().unwrap();
                    let mut r = BufReader::new(conn);
                    loop {
                        let mut line = String::new();
                        if r.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        let mut parts = line.split_whitespace();
                        let method = parts.next().unwrap_or("").to_string();
                        let path = parts.next().unwrap_or("").to_string();
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
                        seen.lock().unwrap().push(Req {
                            method,
                            path,
                            headers,
                            body,
                        });
                        w.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                            .unwrap();
                    }
                });
            }
        });
        (port, seen)
    }

    #[test]
    fn uploads_each_entry_as_a_signed_object() {
        let (port, seen) = fake_s3();
        let config = format!(
            r#"
[s3]
endpoint = "http://127.0.0.1:{port}"
bucket = "audit-bucket"
region = "us-east-1"
prefix = "test/prefix"
access_key_id_secret = "S3_KEY_ID"
secret_access_key_secret = "S3_SECRET"
"#
        );
        let env = Env::start(&config);
        env.set("S3_KEY_ID", "AKIDEXAMPLE");
        env.set("S3_SECRET", "fake-s3-secret-for-tests");
        let out = env.run(
            &["get", "S3_KEY_ID", "--reason", "trigger an upload"],
            None,
            &[],
        );
        assert_eq!(out.status.code(), Some(0));

        let t = Instant::now();
        while seen.lock().unwrap().len() < 3 {
            assert!(
                t.elapsed() < Duration::from_secs(15),
                "uploads did not arrive"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        let reqs = seen.lock().unwrap().clone();
        let log = fs::read_to_string(env.dir.join("audit.jsonl")).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        for (i, r) in reqs.iter().enumerate() {
            assert_eq!(r.method, "PUT");
            let host = bouncer::util::hostname();
            let key = r.path.strip_prefix("/audit-bucket/").unwrap();
            let entry: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
            let expect_key = bouncer::s3::object_key(
                "test/prefix",
                &host,
                entry["ts"].as_str().unwrap(),
                entry["seq"].as_u64().unwrap(),
            );
            assert_eq!(key, bouncer::s3::uri_encode(&expect_key, true));
            assert_eq!(entry["seq"].as_u64().unwrap(), i as u64 + 1);
            assert_eq!(std::str::from_utf8(&r.body).unwrap(), lines[i]);

            let h = &r.headers;
            assert_eq!(
                h["x-amz-content-sha256"],
                bouncer::util::sha256_hex(&r.body)
            );
            let auth = &h["authorization"];
            let date = &h["x-amz-date"];
            let prefix = format!(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/{}/us-east-1/s3/aws4_request, \
                 SignedHeaders=content-md5;host;x-amz-content-sha256;x-amz-date, Signature=",
                &date[..8]
            );
            assert!(auth.starts_with(&prefix), "{auth}");
            let sig = &auth[prefix.len()..];
            assert!(sig.len() == 64 && sig.bytes().all(|b| b.is_ascii_hexdigit()));

            // Re-sign from what the server actually received.
            let signed = [
                ("content-md5", h["content-md5"].clone()),
                ("host", h["host"].clone()),
                ("x-amz-content-sha256", h["x-amz-content-sha256"].clone()),
                ("x-amz-date", date.clone()),
            ];
            let again = bouncer::s3::authorization(
                &bouncer::s3::SignRequest {
                    method: "PUT",
                    path: &r.path,
                    query: "",
                    headers: &signed,
                    payload_sha256: &h["x-amz-content-sha256"],
                    region: "us-east-1",
                    service: "s3",
                    amz_date: date,
                },
                &bouncer::s3::Credentials {
                    access_key_id: "AKIDEXAMPLE".into(),
                    secret_access_key: "fake-s3-secret-for-tests".into(),
                },
            );
            assert_eq!(&again, auth);
        }
        // The cursor reaches the end of the log once everything is uploaded.
        let t = Instant::now();
        loop {
            let cursor =
                fs::read_to_string(env.dir.join("audit.jsonl.s3cursor")).unwrap_or_default();
            if cursor.trim() == log.len().to_string() {
                break;
            }
            assert!(
                t.elapsed() < Duration::from_secs(5),
                "cursor {cursor} != {}",
                log.len()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}
