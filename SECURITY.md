# Security

## Reporting a problem

Please report security problems privately through GitHub's private vulnerability reporting for this repository (Security tab, "Report a vulnerability"), not in a public issue. Include what you found, how to reproduce it, and which version or commit you tested. You should get a reply within a week.

There is no bug bounty. bouncer is provided as is, without warranty and without liability (see the README and the MIT license).

## What bouncer is

A local secret store for LLM agents that records, for every secret released, who asked (kernel peer credentials and the process tree), from which agent session, and why. The record is an audit log chained with HMAC-SHA256 under a key derived from the vault key, and it can be copied to sinks the host cannot rewrite. Optionally, an LLM judges each request before release.

## What it protects against

- Agents reading credentials from files, shell history or other projects: they ask bouncer instead, and every request is recorded with its reason.
- In dedicated-user mode (Linux), agents running as your login user copying the vault, key or audit log, inspecting the daemon, or changing secrets. The daemon runs as its own user with no capabilities; a separate helper keeps only the two capabilities needed to read callers' environments.
- Silent edits to the audit log by anyone without the vault key, rolled-back vault files, and audit logs cut back past a change. Removal of the most recent reads is caught against an anchored head or a sink.
- Secrets in core dumps or swap (core dumps off; memory locked on Linux), and secret buffers left in freed memory (wiped on drop).
- A socket planted by another user: clients check the daemon's uid before sending anything.

## What it does not protect against

- Root, or anything running as the daemon's user. In same-user mode that is you and every process you run, so same-user mode gives accountability, not isolation.
- An agent that gives a misleading reason, or talks the admission model round. Both are recorded, not prevented.
- Misuse of a secret after it is released: copying it, encoding it, sending it elsewhere. `exec` redaction only replaces exact values in the child's stdout and stderr.
- Spoofed session variables. They come from process environments, which whoever starts a process controls. The log records every value it sees and the pid it came from.
- Removal of the most recent audit entries when no head was anchored and no sink is configured.
- A compromised host, kernel, or Rust toolchain and dependencies.

Read "Threat model" and "Caller attribution" in the README for details.
