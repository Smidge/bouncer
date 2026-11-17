# bouncer

A small local secret store for LLM agents. An agent asks for a secret by name and has to say why. The daemon releases it and records who asked, from which process tree and agent session, when, and why, in an audit log that is chained with a keyed MAC. Secret values are not written to the log.

By default bouncer does not judge the reason: any caller with a long enough reason gets the secret, and the point is accountability. When an agent uses a token, you can see which session asked for it and what it said it was doing. An optional admission check asks an LLM whether the reason justifies the request before anything is released (see [Admission check](#admission-check)).

- One binary, about 2.5 MB with the network features and 1.0 MB without (release build, stripped, macOS arm64). No async runtime.
- Secrets stay decrypted in the daemon's memory. A `get` over the socket takes about 75 µs at p50 and 160 µs at p99, including attribution and the audit write (see [Performance](#performance)).
- The vault is one XChaCha20-Poly1305 encrypted file with a generation counter, so a rolled-back vault is detected.
- Audit entries can also go to S3-compatible buckets, InfluxDB, a webhook, a mirror file or syslog.

Linux and macOS only.

## No warranty

bouncer is provided as is, without warranty of any kind, express or implied, as the [MIT license](LICENSE) says. The authors accept no liability for any disclosure, loss or misuse of secrets, or any other damage, arising from its use. It is a young project that has not had an independent security audit. You are responsible for deciding whether it fits your threat model; read [Threat model](#threat-model) and [SECURITY.md](SECURITY.md) first.

## What it is and is not

bouncer gives you a record of which agent session used which credential and why, and it keeps credentials out of agents' context windows and shell history. Run as a separate user, it also stops agents from copying the vault and key files.

It is not a sandbox. Anything that can act as the daemon's user, or as root, can read every secret. A secret released to an agent is out of bouncer's hands. The reason, the session ID and the admission model's verdict are all things an agent can try to fake or talk round.

## Install

```sh
cargo install --git https://github.com/Smidge/bouncer
# without the HTTP client (no S3/InfluxDB/webhook sinks or admission check, no TLS stack):
cargo install --git https://github.com/Smidge/bouncer --no-default-features
```

Pushing a `v*` tag runs a release workflow that builds Linux x86_64 (static, musl) and macOS arm64 binaries. The minimum supported Rust version is 1.88.

## Quick start

```sh
bouncer init                      # creates the key, an empty vault, the audit log and a config template
bouncer serve &                   # or run it as a service, see below

printf %s "$GITHUB_TOKEN" | bouncer set GITHUB_TOKEN --desc "GitHub PAT, repo scope" --tag work
bouncer ls
bouncer get GITHUB_TOKEN --reason "list open PRs on the docs repo"
bouncer log --tail 5
bouncer status                    # daemon state, audit head, sink health
bouncer doctor                    # checks permissions and setup
```

`set` reads the value from stdin and never from arguments. When stdin is a terminal it prompts with echo off, and Ctrl-C restores the terminal. One trailing newline is stripped unless you pass `--raw`.

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

`NAME` becomes an environment variable of the same name. Names that are not valid variable names are upper-cased with other characters turned into `_` (`work/db-url` becomes `WORK_DB_URL`), or you can choose one with `NAME=VAR`. Variable names must match `[A-Za-z_][A-Za-z0-9_]*`, and two secrets cannot map to the same variable.

`exec` replaces every occurrence of a secret value in the child's stdout and stderr with `[REDACTED:<n>]`, where n is the secret's position on the command line, including values split across writes. Overlapping matches are merged into one marker. The marker never contains the secret's name. If a value is so short that it appears inside a marker (for example `1`), matches are removed without a marker. Stdout and stderr are redacted separately, so a value printed half to each is not caught. SIGINT, SIGTERM and SIGHUP sent to `bouncer exec` are forwarded to the child; Ctrl-C reaches the child directly. When the child exits, output from background processes that still hold its pipes is read for one more second, then `exec` returns the child's exit code.

### Exit codes

| code | meaning |
|---|---|
| 0 | ok |
| 1 | other error |
| 2 | usage error or missing reason |
| 3 | denied (policy, admission check, unattributable caller, not an admin) |
| 4 | no such secret |
| 5 | daemon not reachable, or busy |
| 6 | the socket is not owned by the expected daemon uid; nothing was sent |
| 7 | the daemon's audit log has failed; nothing is released until it is repaired |
| 8 | `verify-log` or `doctor` found a problem |

Once `exec` has started the command, it returns the command's own exit code.

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

init                          create the key, an empty vault, the audit log and a config template
keygen                        print a new random key (for key_credential / key_command setups)
serve [--accept-vault-mismatch]
get NAME --reason TEXT [-n]   print a secret
exec --reason TEXT NAME[=ENV]... -- CMD [ARGS...]
set NAME [--desc TEXT] [--tag TAG]... [--reason TEXT] [--raw]   (value from stdin)
rm NAME [--reason TEXT]
ls [--json]                   names and metadata, never values
log [--since WHEN] [--thread ID] [--name NAME] [--tail N] [--json]
status [--json]               daemon state, audit head, sink health
verify-log [--expect-head SEQ:HASH] [--daemon]
repair                        after an audit log failure
migrate-log                   move a version 1 audit log aside and start a keyed one
doctor                        check permissions, key source, socket, sinks and admission
paths                         print the paths in use
```

`--since` takes `30m`, `2h`, `7d` or a UTC date or time prefix such as `2026-11-17` or `2026-11-17T09:30`. `--thread` matches any recorded context variable value. `log` and `ls` escape control characters, newlines and bidi overrides when printing, so a reason or description cannot fake log lines or send terminal escape sequences; `--json` prints the raw entries. All writes go through the daemon, which saves the vault and swaps it in memory, so there is nothing to reload.

## Deployment modes

### Same-user mode

Run `bouncer serve` under your own login, for example with [`contrib/bouncer-user.service`](contrib/bouncer-user.service) (`systemctl --user`) or a launchd agent on macOS. This is the simplest setup and attribution works fully on Linux.

It is accountability, not isolation. Anything running as you can read the key and the vault and decrypt them without asking bouncer, read the audit log, and on macOS attach a debugger to the daemon. Encryption at rest then protects only copies of the files (backups, sync folders, another user on the machine). Admin separation (`admin_uids`) is not a security boundary in this mode either, because every caller has the daemon's uid. `bouncer doctor` says so when it finds this setup.

On macOS you can keep the key out of a file with `key_command`, for example the login Keychain:

```sh
bouncer keygen | xargs -I{} security add-generic-password -a "$USER" -s bouncer-key -w {}
```

```toml
key_command = ["security", "find-generic-password", "-a", "me", "-s", "bouncer-key", "-w"]
```

Any process running as you can usually run the same command, so this protects the key from being copied off disk by file-level tools and backups, not from your own user.

### Dedicated-user mode (Linux)

The daemon runs as a `bouncer` system user. Agents running as your login user can reach the socket, but they cannot read the vault, key or log, cannot inspect the daemon's memory, and cannot change secrets. They can still ask for any secret with a reason; the point is that every use goes through the socket and the log.

When `bouncer serve` starts as root with `user = "bouncer"` in the config, it separates privileges the way OpenSSH does:

1. Before any thread or secret exists, it forks an attribution helper. The helper drops every capability except `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH` (needed to read another user's `/proc/<pid>/environ`, which is mode 0400), switches to the `bouncer` uid, sets `no_new_privs`, and only answers "attribute pid X" over a socketpair. It never sees the key, the vault or a client.
2. The main process reads root-only credentials (systemd `$CREDENTIALS_DIRECTORY`), hands `/run/bouncer` to the `bouncer` user, then drops to `bouncer` with no capabilities and only the socket group as a supplementary group, and checks it cannot regain root.

The key is best supplied as an encrypted systemd credential, so it never sits on disk in a readable form. systemd encrypts it with the host key and, when the machine has a TPM, seals it to the TPM.

Setup (replace `you` with your login):

```sh
sudo useradd --system --home-dir /var/lib/bouncer --shell /usr/sbin/nologin bouncer
sudo groupadd bouncer-clients && sudo usermod -aG bouncer-clients you   # log in again afterwards
sudo install -m 0755 bouncer /usr/local/bin/bouncer
sudo install -d -o bouncer -g bouncer -m 0700 /var/lib/bouncer
sudo install -d -m 0755 /etc/bouncer
sudo install -m 0644 config.toml /etc/bouncer/config.toml               # see below

# The key: keep an offline backup of it, then store it as an encrypted credential.
bouncer keygen > key.backup     # move this somewhere safe, then delete it here
sudo install -d -m 0700 /etc/credstore.encrypted
sudo systemd-creds encrypt --name=bouncer-key key.backup /etc/credstore.encrypted/bouncer-key

sudo systemd-run --pipe --wait -p User=bouncer \
  -p LoadCredentialEncrypted=bouncer-key:/etc/credstore.encrypted/bouncer-key \
  -E BOUNCER_CONFIG=/etc/bouncer/config.toml /usr/local/bin/bouncer init
sudo install -m 0644 contrib/bouncer.service /etc/systemd/system/bouncer.service
sudo systemctl daemon-reload && sudo systemctl enable --now bouncer
```

`/etc/bouncer/config.toml` (999 is the `bouncer` uid from `id -u bouncer`, 1000 is yours):

```toml
user = "bouncer"
socket = "/run/bouncer/bouncer.sock"
socket_mode = "0660"
socket_group = "bouncer-clients"
admin_socket = "/run/bouncer/admin.sock"
allowed_uids = [1000]
server_uid = 999
vault = "/var/lib/bouncer/vault.bin"
audit_log = "/var/lib/bouncer/audit.jsonl"
key_credential = "bouncer-key"
```

Clients read the same config file (`export BOUNCER_CONFIG=/etc/bouncer/config.toml`), which tells them the socket and the uid the daemon must run as. Changes go through the admin socket as the `bouncer` user:

```sh
printf %s "$TOKEN" | sudo -u bouncer env BOUNCER_CONFIG=/etc/bouncer/config.toml \
  bouncer --socket /run/bouncer/admin.sock set GITHUB_TOKEN --reason "rotate PAT"
sudo -u bouncer env BOUNCER_CONFIG=/etc/bouncer/config.toml bouncer verify-log --daemon
```

[`contrib/bouncer.service`](contrib/bouncer.service) limits the start-up phase with `CapabilityBoundingSet` and runs with `NoNewPrivileges`, `LimitCORE=0`, `PrivateDevices`, `ProtectSystem=strict`, `ProtectKernel*`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `SystemCallFilter=@system-service` and `MemoryDenyWriteExecute`. The CI job `multiuser` runs [`ci/multiuser.sh`](ci/multiuser.sh) against that unit: it checks the daemon runs as `bouncer` with no capabilities and the helper with exactly the two, that an `agent` user is attributed across uids, and that the agent cannot read the vault, key or log, inspect the daemon, change secrets or get a client to talk to a socket it planted.

Without systemd, `sudo bouncer serve` with the same config does the same privilege drop; use `key = "/var/lib/bouncer/key"` (a 0600 file owned by `bouncer`) instead of the credential.

macOS has no equivalent of the helper, so dedicated-user mode is Linux only; `bouncer serve` refuses to run as root on macOS.

## Paths

| | Linux | macOS |
|---|---|---|
| config | `$XDG_CONFIG_HOME/bouncer/config.toml` (`~/.config/bouncer/config.toml`) | `~/Library/Application Support/bouncer/config.toml` |
| key | `~/.config/bouncer/key` | `~/Library/Application Support/bouncer/key` |
| vault | `$XDG_DATA_HOME/bouncer/vault.bin` (`~/.local/share/bouncer/vault.bin`) | `~/Library/Application Support/bouncer/vault.bin` |
| audit log | `~/.local/share/bouncer/audit.jsonl` | `~/Library/Application Support/bouncer/audit.jsonl` |
| socket | `$XDG_RUNTIME_DIR/bouncer/bouncer.sock`, or `~/.local/share/bouncer/bouncer.sock` without it | `~/Library/Application Support/bouncer/bouncer.sock` |

`BOUNCER_HOME=/some/dir` puts all of them in one directory. `BOUNCER_CONFIG` or `--config` picks the config file, `BOUNCER_SOCKET` or `--socket` overrides the socket, and `BOUNCER_SERVER_UID` overrides `server_uid` for a client.

bouncer creates directories with mode 0700 and files with mode 0600. It checks paths that already exist too, using `lstat`/`fstat` on the open descriptor rather than the path:

- The vault and log directories must be owned by the daemon's uid, must not be symlinks, and must have no group or other access. The socket directory must not be writable by group or others.
- The vault, the audit log and the lock file must be regular files owned by the daemon's uid with no group or other access.
- The key file and credential files must be regular files, owned by the daemon's uid or root, with mode exactly 0600 or 0400. Files that systemd provides in `$CREDENTIALS_DIRECTORY` may also be 0440, the mode systemd uses inside its private per-service credentials mount. Symlinks are refused.
- An existing socket path is only removed if it is a socket owned by the daemon's uid that nobody is listening on.

Files are written atomically: a temp file with a random name, created with `O_CREAT|O_EXCL|O_NOFOLLOW` at its final mode inside the verified directory, then fsync, rename, and fsync of the directory.

The daemon holds an exclusive `flock` on `bouncer.lock` next to the vault for its lifetime, and `init`, `repair` and `migrate-log` take it too, so a second daemon on the same store fails with a clear message.

## Configuration

The config file is a strict subset of TOML: top-level keys, `[table]` and `[[array]]` headers, strings, integers, booleans and single-line arrays. A hand-written parser for that subset is about 120 lines and keeps the `toml` crate and its dependencies out of the build. Unknown keys are errors. Every key is optional; the values below are the defaults unless the comment says otherwise.

```toml
# Socket and access
socket = "/run/bouncer/bouncer.sock"   # default: see Paths
socket_mode = "0660"
socket_group = "bouncer-clients"       # no default; group of the socket (and its directory in dedicated mode)
admin_socket = "/run/bouncer/admin.sock"  # no default; if set, set/rm are only accepted here (mode 0600)
allowed_uids = [1000]                  # default: the daemon's own uid
admin_uids = [999]                     # who may set/rm; default: the daemon's own uid
server_uid = 999                       # clients: the uid the daemon must run as; default: your own uid
user = "bouncer"                       # Linux: start as root, drop to this user (dedicated-user mode)
max_connections = 64                   # concurrent connections; more get "busy"
request_timeout_ms = 5000              # deadline for receiving a whole request

# Files and key (one of key, key_credential, key_command)
vault = "/var/lib/bouncer/vault.bin"
audit_log = "/var/lib/bouncer/audit.jsonl"
key = "/var/lib/bouncer/key"
# key_credential = "bouncer-key"      # $CREDENTIALS_DIRECTORY/bouncer-key (systemd)
# key_command = ["security", "find-generic-password", "-a", "me", "-s", "bouncer-key", "-w"]

# Policy and attribution
min_reason_len = 8
require_write_reason = false           # true: set and rm need --reason
require_attribution = true             # deny get/exec when the caller cannot be attributed
max_chain_depth = 16                   # processes recorded per entry (the walk always goes to pid 1)
context_vars = ["T3CODE_THREAD_ID", "CLAUDE_CODE_SESSION_ID", "CODEX_THREAD_ID", "CODEX_SESSION_ID"]

# Audit log and memory
audit_fsync = "async"                  # or "strict"
mlock = true                           # lock memory so secrets are not swapped (Linux)
deny_debugger = false                  # macOS: PT_DENY_ATTACH

[[sink]]
type = "s3"
name = "s3"                            # default: the type; used for the cursor file
endpoint = "https://s3.us-east-1.amazonaws.com"
bucket = "my-audit-bucket"
region = "us-east-1"
prefix = "bouncer"
path_style = true
access_key_id_file = "/etc/bouncer/s3-key-id"      # or access_key_id_credential = "name"
secret_access_key_file = "/etc/bouncer/s3-secret"  # or secret_access_key_credential = "name"
conditional_put = true                 # send If-None-Match: *
allow_insecure_http = false            # every HTTP sink and the admission check require https by default

[[sink]]
type = "file"
path = "/mnt/backup-disk/bouncer/audit.jsonl"

[[sink]]
type = "influxdb"
endpoint = "https://influx.example.com"
org = "home"
bucket = "audit"
token_file = "/etc/bouncer/influx-token"
measurement = "bouncer_audit"

[[sink]]
type = "http"
url = "https://hooks.example.com/bouncer"
hmac_secret_file = "/etc/bouncer/webhook-secret"   # optional

[[sink]]
type = "syslog"
socket = "/dev/log"                    # default: /dev/log on Linux, /var/run/syslog on macOS
facility = "authpriv"

[admission]
enabled = false
provider = "anthropic"                 # or "openai" (any OpenAI-compatible chat completions API)
endpoint = "https://api.anthropic.com/v1/messages"  # default depends on provider
model = "claude-opus-5-5"              # required when enabled
api_key_file = "/etc/bouncer/anthropic-key"        # or api_key_credential = "name"
timeout_ms = 8000
on_error = "deny"                      # or "allow"
system_prompt_file = "/etc/bouncer/admission-prompt.txt"  # optional; a built-in prompt is used otherwise
cache_ttl_secs = 0                     # reuse decisions for the same (session, secrets, reason)
history = 5                            # recent requests from the same session given as context
```

Credential files (`*_file`) must be mode 0600 or 0400 and owned by the daemon's uid or root. `*_credential = "name"` reads `$CREDENTIALS_DIRECTORY/name`, for systemd `LoadCredential=` or `LoadCredentialEncrypted=`. Sink and admission credentials can no longer come from the vault: anything in the vault can be read by clients. An old `[s3]` table with `access_key_id_secret` is rejected with a message explaining the change; an `[s3]` table with `*_file` keys still works as one S3 sink.

`audit_fsync = "async"` (the default) writes each entry with one `write(2)` before the response goes out, and a background thread fsyncs the log within about 0.5 s. An entry survives a daemon crash but can be lost on a power cut in that window. `"strict"` fsyncs every entry before answering, which costs a few milliseconds per request.

## Caller attribution

For every connection the daemon:

1. Gets the peer pid, uid and gid from the kernel (`SO_PEERCRED` on Linux, `getpeereid` and `LOCAL_PEERPID` on macOS) right after `accept`. Connections from uids that are not in `allowed_uids` or `admin_uids` are answered with "denied" and closed before anything is read. They are counted, and at most one `reject` entry per minute summarises them.
2. On Linux 6.5 and later it also takes a pidfd for the peer (`SO_PEERPIDFD`), and on both systems it records the peer's start time.
3. Attributes the caller before reading the request, so the caller cannot exit or exec away first. It walks the process tree from the caller to pid 1 (`/proc/<pid>/stat`, `cmdline`, `exe`, `environ` on Linux; `proc_pidinfo`, `proc_pidpath` and `sysctl(KERN_PROCARGS2)` on macOS). It records pid, uid, executable and a shortened argv for the first `max_chain_depth` processes, and the number of ancestors walked. The walk stops at 512 processes and sets `chain_truncated`.
4. Reads the configured context variables from every process's initial environment. Agent harnesses such as T3 Code, Claude Code and Codex set session variables like `T3CODE_THREAD_ID` or `CLAUDE_CODE_SESSION_ID`. The value from the oldest ancestor that has the variable is the primary value, recorded with its pid. Every other distinct value seen below it is recorded too, with its pid (up to 8 per variable, each cut to 256 characters).
5. Checks that the peer is still the same process (its pidfd is alive and its start time is unchanged). Otherwise the attribution is marked `unavailable`.
6. Records the caller's working directory and the host name.

Nothing is cached between requests, because a process can exec into another program with the same pid and start time, or rewrite its environment block.

If the caller's own process cannot be read (it exited, a pid of 0 from another pid namespace, a read failure), the attribution is `unavailable` with the reason, and `get` and `exec` are denied while `require_attribution = true` (the default). If some ancestor with the caller's uid cannot be read, the attribution is `partial` and the request goes ahead.

Session variables are advisory. A process can start a child with any environment it likes, so a value only tells you what the agent harness, or whatever started the caller, put there. Recording every value with its pid shows when something below the harness set a different one. Attribution does not help when the caller runs outside the agent's process tree, for example a process started through a detached daemon or a double fork, which is reparented to init and keeps whatever environment it was given.

On macOS the kernel hides the environment of Apple platform binaries such as `/bin/sh`, `/bin/bash` and `/bin/zsh`, even from the same user. Those chain entries show `"env": false` and make the attribution `partial`. A variable that first appears in a system shell's environment can only be read from processes below it, which makes it easier to spoof on macOS.

In dedicated-user mode the attribution helper (see above) reads other users' processes. `/proc` mounted with `hidepid=` hides them and makes every attribution `unavailable`.

## Admission check

With `[admission] enabled = true`, after the reason check passes, bouncer asks an LLM whether to release the secret. The model gets one JSON object: the operation, each secret's name, description and tags, the reason, the caller's uid, session ID, working directory, context values and process chain, and the last `history` requests from the same session with their decisions. It must answer with exactly `{"decision": "allow" | "deny", "reasoning": "..."}`. The decision and reasoning go into the audit entry (`admission`), and the reasoning is shown to the requester on stderr (and in the JSON response).

Everything the caller supplies is treated as untrusted data. It is sent only inside a JSON block between `<request_json>` tags, with `<` and `>` escaped so text in a reason cannot close the block, and the system prompt tells the model to ignore instructions in it and to treat such attempts as a reason to deny. Any other reply (extra text, extra keys, a refusal), an HTTP error or a timeout is handled by `on_error`, which defaults to deny.

Tag a secret `admission/always` to require the check even when `[admission]` is disabled (the request is then denied, saying so), or `admission/never` to skip it. Both providers use the existing HTTP client with no redirects. Anthropic is called with the Messages API (`anthropic-version: 2026-10-21`); `provider = "openai"` works with any OpenAI-compatible chat completions endpoint.

The model is a filter, not a security boundary. A determined agent can write a convincing reason, and the check adds the model's latency to every `get` it covers. Choose a fast model and keep `on_error = "deny"`.

## Audit log

The log is JSON Lines, one entry per `get`, `exec`, `set`, `rm` and `ls`, including denials and misses, plus `init`, `start`, `abort`, `reject` and `accept_vault_mismatch` records. Example (wrapped here; it is one line in the file):

```json
{"ts":"2026-11-17T10:42:07.318Z","seq":42,"log_id":"5b0e...","op":"get","names":["GITHUB_TOKEN"],
 "reason":"push the docs fix branch and open a PR","decision":"allow","result":"ok",
 "policy":"require-reason","host":"devbox","peer":{"uid":1000,"gid":1000,"pid":48211},
 "attribution":{"status":"ok","cwd":"/home/me/src/docs",
   "context":{"CLAUDE_CODE_SESSION_ID":{"value":"6d1f0c2e-...","pid":47990}},
   "chain":[{"pid":48211,"uid":1000,"exe":"/usr/local/bin/bouncer","argv":"bouncer get GITHUB_TOKEN --reason push the docs fix branch and open a PR"},
            {"pid":48190,"uid":1000,"exe":"/usr/bin/bash","argv":"/bin/bash -c bouncer get GITHUB_TOKEN ..."},
            {"pid":47990,"uid":1000,"exe":"/home/me/.local/bin/claude","argv":"claude"}],
   "ancestors":9},
 "prev":"9c1e4b...","mac":"03f9fe..."}
```

| field | meaning |
|---|---|
| `ts` | RFC 3339 UTC with milliseconds |
| `seq` | 1 for the first entry, then +1 per entry |
| `log_id` | random, fixed for the life of the log |
| `op` | `get`, `exec`, `set`, `rm`, `ls`, or a record type above |
| `decision`, `why` | `allow` or `deny`, and the reason for a denial |
| `result` | `ok`, `denied`, `not_found` or `error` |
| `policy` | what decided: `require-reason`, `require-attribution`, `admission` or `admin` |
| `admission` | the model's decision and reasoning, if it was asked |
| `txn`, `vault_gen`, `vault_hash` | for changes: transaction id, the new vault generation and the SHA-256 of the new vault file |
| `peer` | uid, gid and pid from the kernel |
| `attribution` | see [Caller attribution](#caller-attribution) |
| `prev` | the previous entry's `mac` (64 zeros for the first) |
| `mac` | HMAC-SHA256 of this line up to `,"mac"`, under a key derived from the vault key |

Reasons are cut at 1000 characters, descriptions at 500, context values at 256, argv at 8 arguments of 80 characters. An entry is never longer than 64 KiB: if one would be, its chain and context are cut and it gets `"truncated": true`.

### What the log can and cannot show

Every entry carries a MAC under a key only the daemon has, and `prev` links it to the one before. Without the vault key nobody can write a valid entry, so editing, inserting, removing or reordering entries breaks verification. The daemon verifies the whole log from seq 1 every time it starts and refuses to serve if verification fails.

Removing entries from the end leaves a valid, shorter log. bouncer catches that in two ways:

- Changes are tied to the vault. Every change records the new vault generation and file hash. At start-up the daemon compares the vault file with the last state the log committed to, and refuses to serve if they differ: a rolled-back vault, or a log cut back past a change, is caught. `bouncer serve --accept-vault-mismatch` starts anyway and records an `accept_vault_mismatch` entry. A crash in the few milliseconds between logging a change and saving the vault looks the same as a one-step rollback, so it also needs the flag (the error message says when this is the likely cause).
- Heads can be anchored elsewhere. `bouncer status` prints the current head as `SEQ:MAC`. Store it somewhere this host cannot write (a note, a ticket, another machine), or let a sink carry the entries. Later, `bouncer verify-log --expect-head SEQ:MAC` checks the log still contains that entry with that MAC.

`get` entries removed from the end after the last change, and before any anchor, cannot be detected locally. The sinks exist for that. Anyone holding the vault key (root, or the daemon's user) can rewrite the whole log.

`bouncer verify-log` needs the key to check MACs. Without it (for example in dedicated-user mode as another user) it checks the chain structure only and says so; `bouncer verify-log --daemon` asks the daemon to verify with the key (admin uids only).

### When an audit write fails

If writing or fsyncing an entry fails, the daemon truncates the log back to the end of the last complete entry, writes `<audit_log>.failed`, and from then on refuses every `get`, `exec`, `set`, `rm` and `ls` (exit code 7). Restarting does not clear this. Fix the cause (disk full, I/O error), run `bouncer repair` (it cuts any partial entry, verifies the log and removes the marker), then restart the daemon. Background fsync errors in async mode latch the same way. bouncer never rotates the log.

Changes are serialised and audited before they take effect: the daemon writes the `set`/`rm` entry with its transaction id first, then saves the vault, then swaps it in memory. If saving fails it writes an `abort` entry for that transaction and the change never becomes visible.

### Upgrading from version 0.1 logs

Version 0.1 logs used an unkeyed SHA-256 chain. The daemon refuses to start on one and points to `bouncer migrate-log`, which verifies the old chain, renames the file to `audit.jsonl.v1-<ms>`, and starts a keyed log whose first entry records the old log's entry count and head hash. Version 1 vault files are read as generation 0 and rewritten in the new format on the next change.

## Sinks

Each `[[sink]]` gets its own thread, cursor and status. The local log is the spool: a sink reads complete entries past its cursor, but never past what the audit log has fsynced, delivers them, then saves its cursor (`<audit_log>.<name>.cursor`, written atomically and fsynced). The cursor is bound to the log's `log_id`, the destination, and the last delivered entry's seq and MAC. A cursor for another log or destination starts over from the first entry. If the log no longer continues from the cursor (it was rewritten or replaced), the sink stops with an error in `bouncer status` instead of skipping or re-sending. A sink thread that dies is restarted, with backoff from 1 second to 5 minutes; failed deliveries back off the same way. Requests never wait for the network.

Delivery is at least once: an entry delivered just before a crash, but after the last cursor save, is sent again on restart. Entries carry `seq`, `log_id` and `mac`, so receivers can de-duplicate, and each sink carries the head of the log with it.

`bouncer status` shows each sink's last delivered seq, lag behind the head, last success and last error. `bouncer doctor` flags sinks with errors.

| type | what it does |
|---|---|
| `s3` | One object per entry, `<prefix>/<host>/YYYY/MM/DD/<log_id>-<seq>.json`. Signed with AWS SigV4 (implemented in `src/sink/s3.rs` on `hmac` and `sha2`), with `Content-MD5`, which Object Lock requires. Only HTTP 200 and 201 count as success; redirects are not followed. With `conditional_put = true` (default) uploads send `If-None-Match: *`, so the store refuses to replace an existing object, and a 412 answer is treated as "already delivered". If a provider rejects conditional writes, the error says to set `conditional_put = false`. Works with AWS S3, Cloudflare R2 (`region = "auto"`, endpoint `https://<account>.r2.cloudflarestorage.com`), iDrive E2, MinIO and others. |
| `file` | Appends each line, unchanged, to another file and fsyncs it, for example on another disk. On restart it reads the mirror's last line so it does not append entries twice. |
| `influxdb` | InfluxDB v2 `POST /api/v2/write` with line protocol, in batches of up to 500. Tags: `op`, `secret` (names), `decision`, `host`, `thread` (first context variable). Fields: `seq`, `reason`, `result`, `why`, `policy`, `attribution`, `uid`, `pid`, `log_id`. Values are escaped; newlines never reach the line protocol. |
| `http` | POSTs each entry's JSON line with `X-Bouncer-Seq` and `X-Bouncer-Log-Id`. With `hmac_secret_file`, also `X-Bouncer-Signature: sha256=<hex HMAC-SHA256(secret, body)>`. Any 2xx counts as delivered. |
| `syslog` | RFC 5424 over the local datagram socket; on systemd machines this lands in the journal. Denials are logged at `notice`, everything else at `info`. Messages over 8 KiB are cut and marked. Local syslog can drop messages, so treat it as a view, not a copy. |

The S3 sink's key needs `s3:PutObject` on the prefix and nothing else. Object Lock in compliance mode is what stops anyone, including the bucket owner, from deleting or overwriting objects during the retention period; bouncer does not configure it, so set it on the bucket.

A new sink type implements the `Sink` trait in `src/sink/mod.rs` (`fingerprint`, `send`, optionally `batch_size` and `already_has`) and adds a config variant.

## Crypto

- The vault is encrypted with XChaCha20-Poly1305 (RustCrypto `chacha20poly1305`) under a 256-bit key. Every save uses a fresh random 192-bit nonce, so nonces do not repeat in practice.
- The 16-byte header (magic, format version, generation) is authenticated as associated data, so changing any byte of the file, including the generation, makes it fail to load. Tests flip every byte of a vault and check it fails, and check the cipher against the XChaCha20-Poly1305 test vector from draft-irtf-cfrg-xchacha-03.
- The generation counter goes up by one on every change and is recorded in the audit log, which is how a rolled-back vault is detected (see [Audit log](#audit-log)).
- The key is 32 random bytes from the OS (`getrandom`), stored as 64 hex characters in a file (mode 0600 or 0400), an encrypted systemd credential, or wherever `key_command` gets it from. In memory it is wiped on drop.
- The audit chain key is HMAC-SHA256(vault key, "bouncer audit chain v1"), so the vault key and the chain key are never used for the same thing.
- Decrypted secrets, request and response buffers and the plaintext vault are wiped when dropped (`zeroize`). serde's internal buffers are not, and a secret released to a client is copied into that client's memory.
- The daemon disables core dumps (`RLIMIT_CORE=0`), on Linux marks itself non-dumpable (`PR_SET_DUMPABLE=0`, which also stops same-uid `ptrace` and `/proc/<pid>/mem` reads), and locks its memory with `mlockall` so secrets are not swapped. Locking all future allocations needs a high `RLIMIT_MEMLOCK` (the system unit sets `LimitMEMLOCK=infinity`); with a low limit bouncer locks what it has at start-up and prints a warning. macOS has no working `mlockall` (its swap is encrypted); `deny_debugger = true` sets `PT_DENY_ATTACH`.

Vault file layout (version 2):

```text
offset  size   field
0       7      magic "BOUNCER"
7       1      format version (2)
8       8      generation, u64 little-endian
16      24     XChaCha20-Poly1305 nonce, random per write
40      n+16   ciphertext and tag; associated data = bytes 0..16
```

The plaintext is JSON: `{"secrets": {"NAME": {"value", "desc", "tags", "created", "updated"}}}`. Secret names and tags are 1 to 128 characters of `A-Z a-z 0-9 _ . - /`. Values are UTF-8 text of up to 256 KiB.

## Threat model

bouncer provides accountability, and in dedicated-user mode it keeps your agents away from the files. It is not a sandbox. [SECURITY.md](SECURITY.md) has a short version and says how to report problems.

- **Same-uid callers can bypass it.** If the daemon runs as you, any process running as you can read the key and vault files, or attach a debugger to the daemon on macOS, without going through the socket. Use dedicated-user mode to make the socket the only way in for your agents.
- **Root bypasses everything,** in every mode.
- **The reason is whatever the agent says.** bouncer records it. The optional admission model judges it, but a model can be persuaded.
- **Attribution is advisory.** The peer uid and pid come from the kernel. Session variables come from process environments, which whoever starts a process controls; see [Caller attribution](#caller-attribution).
- **Released values are out of bouncer's hands.** `exec` redaction covers the child's stdout and stderr, only exact matches, each stream separately. It does not catch encoded or transformed values, or values the child writes to files or the network.
- **The audit log is tamper-evident, not tamper-proof.** Without the key nobody can forge entries, and cutting the log back past a change is caught. Cutting off the last few reads is only caught against an anchored head or a sink. Anyone with the key can rewrite the whole log. Ship it to an Object Lock bucket if you need a copy the host cannot change.
- **Argv is logged.** The chain records shortened argv of the caller and its ancestors. If a process was started with a secret on its command line, part of it can end up in the log.
- **Memory.** Secrets live decrypted in the daemon's memory. Core dumps are off, memory is locked where possible and buffers are wiped on drop, but anyone who can read the daemon's memory (root, or its own uid on macOS) can read the secrets.
- **Denial of service.** An allowed uid can hold up to `max_connections` connections for `request_timeout_ms` each, or fill the disk the log is on, after which the daemon stops releasing secrets until repaired.

## Performance

Measured on an Apple M-series laptop (macOS, release build), with `examples/latency.rs` against a running daemon, with a process tree five deep:

| | p50 | p90 | p99 |
|---|---|---|---|
| socket `get` (connect, attribution, request, audit write, response) | 74 µs | 92 µs | 160 µs |
| `bouncer get` CLI, including process start-up | 2.1 ms | 2.5 ms | 3.8 ms |

Version 0.1 measured 39 µs at p50 for the socket `get`. Most of the difference is walking the whole process tree for every request, without a cache, and checking the caller is unchanged afterwards. `audit_fsync = "strict"` adds an fsync per request (a few milliseconds on macOS). The admission check adds the model's response time.

Run it yourself:

```sh
printf fake-value | bouncer set BENCH
cargo run --release --example latency -- "$(bouncer paths | sed -n 's/^socket *//p')" 10000
```

## Policy

```rust
pub trait Policy: Send + Sync {
    fn name(&self) -> &'static str;
    fn decide(&self, input: &PolicyInput) -> Decision; // Allow | Deny(why), non-exhaustive
    fn verdict(&self, input: &PolicyInput) -> Verdict { ... } // decision plus reasoning for the log
}
```

`PolicyInput` carries the operation, metadata of the requested secrets (name, description, tags; never values), the caller (kernel peer credentials, attribution and session ID) and the reason. bouncer ships `AllowAll`, `RequireReason { min_len }` and the admission check. The daemon runs `RequireReason` for `get` and `exec`, then the admission check if it applies. `set` and `rm` are allowed for `admin_uids` (on the admin socket, if there is one) and always logged.

## Roadmap

- **Approvals.** An `Ask` decision that holds the request and pushes an approve/deny prompt to a phone or desktop, with a timeout.
- **Per-secret policies.** Rules by tag or name beyond `admission/always` and `admission/never`.
- **Secure Enclave key on macOS.**
- **`security` CLI shim.** Answer `security find-generic-password -s NAME -w` through bouncer so existing scripts get logged without changes.
- Log rotation with a chain link across files.

## License

MIT. See [No warranty](#no-warranty).
