# bouncer

A small local secret store for LLM agents. An agent asks for a secret by name and has to say why. The daemon releases it and writes who asked, from which process tree and agent session, when, and why, to a hash-chained audit log. It never logs the value.

Today bouncer does not decide who gets what. Any caller with a non-empty reason gets the secret. The point is accountability: when an agent uses a token, you can see which session asked for it and what it said it was doing. The release decision sits behind a `Policy` trait so an LLM judge can be added later (see [Roadmap](#roadmap)).

- One binary, about 2 MB with the S3 sink and 0.7 MB without (release build, stripped, macOS arm64). No async runtime.
- Secrets stay decrypted in the daemon's memory. A `get` over the socket takes about 40 µs at p50 and 65 µs at p99, including the audit write. The `bouncer get` CLI takes about 1.5 ms, which is mostly process start-up (see [Performance](#performance)).
- The vault is a single XChaCha20-Poly1305 encrypted file, written atomically.
- The daemon finds the caller from the OS (peer credentials and the process tree), not from anything the client says.
- Audit entries can also go to an S3-compatible bucket, one object per entry, so Object Lock buckets work.

Linux and macOS only.

## Install

```sh
cargo install --git https://github.com/Smidge/bouncer
# without the S3 sink (no TLS stack, smaller binary):
cargo install --git https://github.com/Smidge/bouncer --no-default-features
```

Pushing a `v*` tag runs a release workflow that builds Linux x86_64 (static, musl) and macOS arm64 binaries.

## Quick start

```sh
bouncer init                      # creates the key, an empty vault and a config template
bouncer serve &                   # or run it as a service, see below

printf %s "$GITHUB_TOKEN" | bouncer set GITHUB_TOKEN --desc "GitHub PAT, repo scope" --tag work
bouncer ls
bouncer get GITHUB_TOKEN --reason "list open PRs on the docs repo"
bouncer log --tail 5
bouncer verify-log
```

`set` reads the value from stdin and never from arguments. When stdin is a terminal it prompts with echo off. One trailing newline is stripped unless you pass `--raw`.

## Using it from an agent

Fetch a value:

```sh
bouncer get GITHUB_TOKEN --reason "push the docs fix branch and open a PR"
```

The value goes to stdout with no trailing newline (`-n` adds one), so `$(bouncer get ...)` works. The reason can also come from `BOUNCER_REASON`.

Better, run the command with the secret in its environment and keep the value out of the transcript:

```sh
bouncer exec --reason "publish release 1.4.2 to npm" NPM_TOKEN -- npm publish
bouncer exec --reason "query staging db for the bug report" work/db-url=DATABASE_URL -- psql -c 'select 1'
```

`NAME` becomes an environment variable of the same name. Names that are not valid variable names are upper-cased with other characters turned into `_` (`work/db-url` becomes `WORK_DB_URL`), or you can choose one with `NAME=VAR`. Any occurrence of a secret value in the child's stdout or stderr is replaced with `[REDACTED:NAME]`, including values split across writes. The child's exit code is passed through.

Exit codes: `0` ok, `1` error, `2` usage error or missing reason, `3` denied, `4` no such secret, `5` daemon not reachable. A missing reason prints a message telling the caller to supply one.

### Snippet for CLAUDE.md / AGENTS.md

```markdown
## Secrets

Get credentials from `bouncer`, never from files, shell history or other projects.

- Prefer `bouncer exec --reason "<why>" NAME -- <command>`, which puts the secret in the
  command's environment and redacts it from the output.
- If you need the value itself: `bouncer get NAME --reason "<why>"`.
- `bouncer ls` lists the available names.
- The reason is required and is logged with your session ID. Name the task, not the
  secret: "deploy docs site to staging", not "need token".
- Do not print, echo or write secret values to files, commits or messages.
```

## Commands

```text
bouncer [--config FILE] [--socket PATH] <command>

init                          create the key, an empty vault and a config template
serve                         run the daemon
get NAME --reason TEXT [-n]   print a secret
exec --reason TEXT NAME[=ENV]... -- CMD [ARGS...]
set NAME [--desc TEXT] [--tag TAG]... [--raw]   (value from stdin)
rm NAME
ls [--json]                   names and metadata, never values
log [--since WHEN] [--thread ID] [--name NAME] [--tail N] [--json]
verify-log                    check the audit log's hash chain
paths                         print the paths in use
```

`--since` takes `30m`, `2h`, `7d` or a UTC date or time prefix such as `2026-11-17` or `2026-11-17T09:30`. `--thread` matches any recorded context variable value. `set` and `rm` accept an optional `--reason`. All writes go through the daemon, which saves the vault and swaps it in memory, so there is nothing to reload.

## Paths

| | Linux | macOS |
|---|---|---|
| config | `$XDG_CONFIG_HOME/bouncer/config.toml` (`~/.config/bouncer/config.toml`) | `~/Library/Application Support/bouncer/config.toml` |
| key | `~/.config/bouncer/key` | `~/Library/Application Support/bouncer/key` |
| vault | `$XDG_DATA_HOME/bouncer/vault.bin` (`~/.local/share/bouncer/vault.bin`) | `~/Library/Application Support/bouncer/vault.bin` |
| audit log | `~/.local/share/bouncer/audit.jsonl` | `~/Library/Application Support/bouncer/audit.jsonl` |
| socket | `$XDG_RUNTIME_DIR/bouncer/bouncer.sock`, or `/tmp/bouncer-<uid>/bouncer.sock` without it | `~/Library/Application Support/bouncer/bouncer.sock` |

`BOUNCER_HOME=/some/dir` puts all of them in one directory. `BOUNCER_CONFIG` or `--config` picks the config file, and `BOUNCER_SOCKET` or `--socket` overrides the socket. Directories bouncer creates are mode 0700, and the key, vault and log are 0600. On Linux the key and vault live in different directories, so backing up your data directory does not copy the key with it.

## Configuration

The config file is a strict subset of TOML: top-level keys, one `[s3]` table, strings, integers, booleans and single-line arrays. A hand-written parser for that subset is about 100 lines and keeps the `toml` crate and its dependencies out of the build. Unknown keys are errors. Every key is optional:

```toml
socket = "/run/bouncer/bouncer.sock"
socket_mode = "0600"          # "0666" plus allowed_uids when the daemon has its own user
allowed_uids = [1000]         # who may connect; default: the daemon's own uid
key = "/etc/bouncer/key"
vault = "/var/lib/bouncer/vault.bin"
audit_log = "/var/lib/bouncer/audit.jsonl"
audit_fsync = "async"         # or "strict", see below
min_reason_len = 8            # shorter reasons are denied
max_chain_depth = 16          # ancestors recorded per request
context_vars = ["T3CODE_THREAD_ID", "CLAUDE_CODE_SESSION_ID", "CODEX_THREAD_ID", "CODEX_SESSION_ID"]

[s3]
endpoint = "https://s3.us-east-1.amazonaws.com"
bucket = "my-audit-bucket"
region = "us-east-1"
prefix = "bouncer"
path_style = true
access_key_id_secret = "AUDIT_S3_ACCESS_KEY_ID"           # names of secrets in this vault
secret_access_key_secret = "AUDIT_S3_SECRET_ACCESS_KEY"
```

`audit_fsync = "async"` (the default) writes each entry with one `write(2)` before the response goes out, and a background thread fsyncs the log within about 0.5 s. An entry survives a daemon crash but can be lost on a power cut in that window. `"strict"` fsyncs every entry before releasing the secret, which costs a few milliseconds per request.

## Caller attribution

For every request the daemon:

1. Gets the peer pid, uid and gid from the kernel: `SO_PEERCRED` on Linux, `getpeereid` and `LOCAL_PEERPID` on macOS.
2. Walks up the process tree (`/proc/<pid>/stat`, `cmdline`, `exe`, `environ` on Linux; `proc_pidinfo`, `proc_pidpath` and `sysctl(KERN_PROCARGS2)` on macOS), recording pid, uid, executable and a shortened argv for up to `max_chain_depth` processes.
3. Reads the configured context variables from each process's initial environment. Agent harnesses such as T3 Code, Claude Code and Codex set session variables like `T3CODE_THREAD_ID` or `CLAUDE_CODE_SESSION_ID`. For each variable bouncer takes the value from the **oldest** ancestor that has it and records that pid. A tool the agent runs can set the variable in its own environment, but it cannot change what its ancestors started with.
4. Records the caller's working directory and the host name.

Per-process details are cached by (pid, start time), so walking long-lived ancestors costs nothing after the first request.

If the daemon cannot read a process's environment, that chain entry gets `"env": false` and the entry's `attribution` field says `partial` (an ancestor with the caller's uid was unreadable) or `unavailable` (the caller itself was unreadable). The request still succeeds.

On Linux, reading another user's `/proc/<pid>/environ` needs `CAP_SYS_PTRACE`. The sample system unit grants it as an ambient capability. Same-user mode needs nothing extra.

On macOS the kernel hides the environment of Apple platform binaries such as `/bin/sh`, `/bin/bash` and `/bin/zsh`, even from the same user. Those chain entries show `"env": false`. Variables set in a non-Apple process, such as the agent harness itself, are still read from there. A variable that first appears in a system shell's environment can only be read from processes below it, which makes it spoofable on macOS. Check the recorded `pid` for each context value if this matters to you.

## Audit log

The log is JSON Lines, one entry per `get`, `exec`, `set` and `rm`, including denials and misses. `ls` is not logged. Example (wrapped here; it is one line in the file):

```json
{"ts":"2026-11-17T10:42:07.318Z","seq":42,"op":"get","names":["GITHUB_TOKEN"],
 "reason":"push the docs fix branch and open a PR","decision":"allow","result":"ok",
 "policy":"require-reason","host":"devbox","peer":{"uid":1000,"gid":1000,"pid":48211},
 "cwd":"/home/me/src/docs","attribution":"ok",
 "context":{"CLAUDE_CODE_SESSION_ID":{"value":"6d1f0c2e-...","pid":47990}},
 "chain":[{"pid":48211,"uid":1000,"exe":"/usr/local/bin/bouncer","argv":"bouncer get GITHUB_TOKEN --reason push the docs fix branch and open a PR"},
          {"pid":48190,"uid":1000,"exe":"/usr/bin/bash","argv":"/bin/bash -c bouncer get GITHUB_TOKEN ..."},
          {"pid":47990,"uid":1000,"exe":"/home/me/.local/bin/claude","argv":"claude"}],
 "prev":"9c1e4b..."}
```

| field | meaning |
|---|---|
| `ts` | RFC 3339 UTC with milliseconds |
| `seq` | increases by one per entry |
| `op` | `get`, `exec`, `set` or `rm` |
| `decision`, `why` | `allow` or `deny`, and the reason for a denial |
| `result` | `ok`, `denied`, `not_found` or `error` |
| `policy` | the policy that decided (`require-reason`; `writes` for set and rm) |
| `peer` | uid, gid and pid from the kernel |
| `chain` | the caller and its ancestors, newest first; argv is cut to 8 arguments of 80 characters |
| `context` | configured session variables, each with the pid it was read from |
| `prev` | hex SHA-256 of the previous line's exact bytes; 64 zeros for the first entry |

Editing, deleting or reordering a line breaks the chain at the next line. `bouncer verify-log` checks every link and every `seq`, then prints the head hash. Someone who can write the log file can still rewrite the whole chain from the point they changed, so keep a copy somewhere they cannot write: the S3 sink, or the head hash noted elsewhere.

If an audit write fails, the daemon refuses to release the secret. The log is never rotated by bouncer.

## S3 sink

With an `[s3]` table, a background thread uploads every audit line as its own object:

```text
<prefix>/<host>/YYYY/MM/DD/<YYYYMMDDTHHMMSSmmmZ>-<seq>.json
```

Objects are never appended to or overwritten, so you can use a bucket with Object Lock in compliance mode. Requests are signed with AWS SigV4 (implemented in `src/s3.rs` on `hmac` and `sha2`) and carry `Content-MD5`, which Object Lock requires. Path-style URLs are the default; set `path_style = false` for virtual-hosted style. This works with AWS S3, Cloudflare R2 (`region = "auto"`, endpoint `https://<account>.r2.cloudflarestorage.com`), iDrive E2, MinIO and other S3-compatible stores.

The sink's own credentials are secrets in the same vault, referenced by name:

```sh
printf %s "$KEY_ID" | bouncer set AUDIT_S3_ACCESS_KEY_ID --desc "audit bucket writer"
printf %s "$SECRET" | bouncer set AUDIT_S3_SECRET_ACCESS_KEY --desc "audit bucket writer"
```

Give that key permission to `s3:PutObject` on the prefix and nothing else. The daemon reads these internally, and those reads are not logged.

The local log is the upload queue. The uploader keeps a byte offset in `<audit_log>.s3cursor` (written atomically and fsynced), uploads every complete line past it, and retries failures with exponential backoff from 1 s to 5 minutes. Requests never wait for the network. After an outage, or when you add the sink to an existing log, it uploads the backlog in order.

## Running as a service

**Same user** (simplest): run `bouncer serve` under your login, for example with [`contrib/bouncer-user.service`](contrib/bouncer-user.service) (`systemctl --user`) or a launchd agent on macOS. Attribution works fully on Linux, but anything running as you can also read the key and vault files.

**Dedicated user** (Linux): run the daemon as a `bouncer` system user so agents running as you cannot read the files. Callers connect over a socket in `/run/bouncer`, and `allowed_uids` limits who may connect. [`contrib/bouncer.service`](contrib/bouncer.service) has the setup steps and a matching config:

```ini
[Unit]
Description=bouncer secret store for agents
Documentation=https://github.com/Smidge/bouncer
After=network-online.target
Wants=network-online.target

[Service]
User=bouncer
Group=bouncer
Environment=BOUNCER_CONFIG=/etc/bouncer/config.toml
ExecStart=/usr/local/bin/bouncer serve
AmbientCapabilities=CAP_SYS_PTRACE
CapabilityBoundingSet=CAP_SYS_PTRACE
NoNewPrivileges=yes
RuntimeDirectory=bouncer
RuntimeDirectoryMode=0755
UMask=0077
ProtectSystem=strict
ReadWritePaths=/var/lib/bouncer
ProtectHome=yes
PrivateTmp=yes
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

In this mode `bouncer log` and `verify-log` need read access to `/var/lib/bouncer/audit.jsonl`, for example through `sudo -u bouncer`.

## Threat model

bouncer provides accountability. It is not a sandbox.

- **Same-uid callers can bypass it.** If the daemon runs as you, any process running as you can read the key and vault files, or attach a debugger to the daemon, without going through the socket. Run the daemon as a separate user to make the socket the only way in for your agents.
- **Root bypasses everything,** in every mode.
- **The reason is whatever the agent says.** bouncer records it and does not check it. A future policy may judge it.
- **Attribution comes from the OS process tree.** The peer pid and uid come from the kernel, and context variables come from the oldest ancestor that has them, so a child process cannot override its session ID. It does not help when the caller runs outside the agent's process tree, for example a process started through a detached daemon or a double fork, which is reparented to init and keeps whatever environment it was given. On macOS it is weaker for variables that only system shells carry (see [Caller attribution](#caller-attribution)).
- **Released values are out of bouncer's hands.** `exec` redaction only covers the child's stdout and stderr, and only exact matches. It does not catch encoded or transformed values, or values the child writes to files or the network.
- **The audit log is tamper-evident, not tamper-proof.** See [Audit log](#audit-log). Ship it to an Object Lock bucket if you need a copy the host cannot change.
- **Argv is logged.** The `chain` records shortened argv of the caller and its ancestors. If a parent process was started with a secret on its command line, part of it can end up in the log.
- **Memory.** Secrets are plain strings in the daemon's memory. bouncer does not lock memory or zero it on drop. A core dump of the daemon contains them.

## Performance

Measured on an Apple M-series laptop (macOS, release build), with `examples/latency.rs` against a running daemon:

| | p50 | p90 | p99 |
|---|---|---|---|
| socket `get` (connect, request, audit write, response) | 39 µs | 45 µs | 64 µs |
| `bouncer get` CLI, including process start-up | 1.5 ms | 1.7 ms | 2.1 ms |
| socket `get` with `audit_fsync = "strict"` | 4.0 ms | 4.3 ms | 5.7 ms |

Run it yourself:

```sh
printf fake-value | bouncer set BENCH
cargo run --release --example latency -- "$(bouncer paths | sed -n 's/^socket *//p')" 10000
```

## Vault format

```text
offset  size   field
0       7      magic "BOUNCER"
7       1      format version (1)
8       24     XChaCha20-Poly1305 nonce, random per write
32      n+16   ciphertext and tag; associated data = bytes 0..8
```

The plaintext is JSON: `{"secrets": {"NAME": {"value", "desc", "tags", "created", "updated"}}}`. The key file holds 32 random bytes as 64 hex characters and must be mode 0600 or bouncer refuses to start. Every save writes a temporary file, fsyncs it, renames it over the vault and fsyncs the directory.

Secret names and tags are 1 to 128 characters of `A-Z a-z 0-9 _ . - /`. Values are UTF-8 text.

## Policy

```rust
pub trait Policy: Send + Sync {
    fn name(&self) -> &'static str;
    fn decide(&self, input: &PolicyInput) -> Decision; // Allow | Deny(why), non-exhaustive
}
```

`PolicyInput` carries the operation, metadata of the requested secrets (name, description, tags; never values), the caller (kernel peer credentials plus the attribution above) and the reason. bouncer ships `AllowAll` and `RequireReason { min_len }`. The daemon uses `RequireReason` with `min_reason_len` for `get` and `exec`, and always rejects an empty reason. `set` and `rm` are always allowed and logged.

## Roadmap

- **LLM policy judge.** A `Policy` that sends the reason, caller attribution and secret metadata to a model and gets back allow, deny, or ask. It would compare the stated reason with what the session is doing, and allow routine requests that match the session's work without prompting. Needs care with latency, caching of repeated decisions, and a fail-closed or fail-open choice when the model is unreachable.
- **Approvals.** An `Ask` decision that holds the request and pushes an approve/deny prompt to a phone or desktop, with a timeout.
- **Per-secret policies.** Rules by tag or name, for example `personal` secrets always need approval and `work` ones need a reason.
- **macOS Keychain-backed key.** Keep the vault key in the login Keychain or Secure Enclave instead of a file.
- **`security` CLI shim.** Answer `security find-generic-password -s NAME -w` through bouncer so existing scripts get logged without changes.
- Log rotation with a chain link across files.

## License

MIT
