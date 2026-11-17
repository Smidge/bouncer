//! bouncer: a small local secret store for LLM agents. Every read needs a reason and is
//! written to a hash-chained audit log, attributed to the calling process tree.

pub mod util;

pub mod audit;
pub mod config;
pub mod peer;
pub mod policy;
pub mod proto;
pub mod redact;
#[cfg(feature = "s3")]
pub mod s3;
pub mod server;
pub mod vault;
