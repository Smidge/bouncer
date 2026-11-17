//! bouncer: a small local secret store for LLM agents. Every read needs a reason and is
//! written to a keyed, hash-chained audit log, attributed to the calling process tree.

pub mod util;

#[cfg(feature = "net")]
pub mod admission;
pub mod audit;
pub mod config;
pub mod harden;
pub mod peer;
pub mod policy;
#[cfg(target_os = "linux")]
pub mod privsep;
pub mod proto;
pub mod redact;
pub mod server;
pub mod sink;
pub mod vault;
