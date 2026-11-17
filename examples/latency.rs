//! Measures `get` latency against a running daemon.
//!
//! ```sh
//! echo -n fake-value | bouncer set BENCH
//! cargo run --release --example latency -- [SOCKET] [ITERATIONS]
//! ```
//!
//! Reports the socket round trip (connect, request, audit write, response) and the full
//! `bouncer get` CLI invocation, which adds process start-up.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::time::{Duration, Instant};

fn percentiles(mut v: Vec<Duration>) -> String {
    v.sort();
    let p = |q: f64| v[((v.len() as f64 * q) as usize).min(v.len() - 1)];
    format!(
        "n={} p50={:?} p90={:?} p99={:?} max={:?}",
        v.len(),
        p(0.50),
        p(0.90),
        p(0.99),
        v[v.len() - 1]
    )
}

fn main() {
    let mut args = std::env::args().skip(1);
    let socket = args
        .next()
        .or_else(|| std::env::var("BOUNCER_SOCKET").ok())
        .expect("pass the socket path or set BOUNCER_SOCKET");
    let n: usize = args.next().map_or(10_000, |s| s.parse().unwrap());
    let req = b"{\"op\":\"get\",\"names\":[\"BENCH\"],\"reason\":\"latency benchmark\"}\n";

    let mut socket_times = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        let mut s = UnixStream::connect(&socket).unwrap();
        s.write_all(req).unwrap();
        let mut resp = Vec::new();
        s.read_to_end(&mut resp).unwrap();
        socket_times.push(t.elapsed());
        assert!(
            resp.starts_with(b"{\"ok\":true"),
            "{}",
            String::from_utf8_lossy(&resp)
        );
    }
    println!("socket get: {}", percentiles(socket_times));

    let bin = std::env::var("BOUNCER_BIN").unwrap_or_else(|_| "target/release/bouncer".into());
    let mut cli_times = Vec::new();
    for _ in 0..(n / 20).max(50) {
        let t = Instant::now();
        let out = Command::new(&bin)
            .args([
                "--socket",
                &socket,
                "get",
                "BENCH",
                "--reason",
                "latency benchmark",
            ])
            .output()
            .unwrap();
        cli_times.push(t.elapsed());
        assert!(out.status.success());
    }
    println!("cli get:    {}", percentiles(cli_times));
}
