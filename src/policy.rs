//! Release policy. Today bouncer ships only simple policies; the `Policy` trait is the hook
//! for a future LLM judge (see ROADMAP in the README).

use crate::peer::{Attribution, PeerCred};
use crate::proto::Op;

/// Metadata about a requested secret. Never includes the value.
pub struct SecretMeta<'a> {
    pub name: &'a str,
    pub desc: Option<&'a str>,
    pub tags: &'a [String],
}

/// Who is asking, as established by the OS.
pub struct Caller<'a> {
    pub peer: PeerCred,
    pub attribution: &'a Attribution,
}

pub struct PolicyInput<'a> {
    pub op: Op,
    pub secrets: Vec<SecretMeta<'a>>,
    pub caller: Caller<'a>,
    pub reason: &'a str,
}

/// A policy's verdict. Non-exhaustive so an `Ask` (human approval) variant can be added later.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Decision {
    Allow,
    Deny(String),
}

pub trait Policy: Send + Sync {
    fn name(&self) -> &'static str;
    fn decide(&self, input: &PolicyInput) -> Decision;
}

/// Releases everything. Accountability only comes from the audit log.
pub struct AllowAll;

impl Policy for AllowAll {
    fn name(&self) -> &'static str {
        "allow-all"
    }
    fn decide(&self, _: &PolicyInput) -> Decision {
        Decision::Allow
    }
}

/// Releases a secret when the reason has at least `min_len` characters after trimming.
pub struct RequireReason {
    pub min_len: usize,
}

impl Policy for RequireReason {
    fn name(&self) -> &'static str {
        "require-reason"
    }
    fn decide(&self, input: &PolicyInput) -> Decision {
        let len = input.reason.trim().chars().count();
        if len == 0 {
            return Decision::Deny("a reason is required".into());
        }
        if len < self.min_len {
            return Decision::Deny(format!(
                "reason is too short ({len} chars, need at least {}); say what you need the secret for",
                self.min_len
            ));
        }
        Decision::Allow
    }
}

/// The policy used by the daemon: reads need a reason; writes are always allowed (and audited).
pub fn default_policy(min_reason_len: usize) -> Box<dyn Policy> {
    Box::new(RequireReason {
        min_len: min_reason_len.max(1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(reason: &'a str, at: &'a Attribution) -> PolicyInput<'a> {
        PolicyInput {
            op: Op::Get,
            secrets: vec![SecretMeta {
                name: "X",
                desc: None,
                tags: &[],
            }],
            caller: Caller {
                peer: PeerCred {
                    uid: 1,
                    gid: 1,
                    pid: 1,
                },
                attribution: at,
            },
            reason,
        }
    }

    #[test]
    fn require_reason() {
        let at = Attribution::default();
        let p = RequireReason { min_len: 8 };
        assert_eq!(
            p.decide(&input("deploying the docs site", &at)),
            Decision::Allow
        );
        assert!(matches!(p.decide(&input("   ", &at)), Decision::Deny(_)));
        assert!(matches!(p.decide(&input("short", &at)), Decision::Deny(_)));
        assert_eq!(AllowAll.decide(&input("", &at)), Decision::Allow);
    }
}
