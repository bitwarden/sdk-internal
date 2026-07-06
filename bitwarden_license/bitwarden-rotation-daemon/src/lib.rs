//! Bitwarden PAM credential rotation daemon library.
//!
//! This crate implements the core logic for the `bw-rotation-daemon` binary,
//! which continuously rotates PAM-managed credentials according to configured
//! policies and schedules.

pub(crate) mod api;
pub(crate) mod auth;
pub(crate) mod cli;
pub(crate) mod config;
pub(crate) mod crypto;
pub(crate) mod error;
pub(crate) mod executor;
pub(crate) mod integrations;
pub(crate) mod policy;
pub(crate) mod resolver;
pub(crate) mod token;
