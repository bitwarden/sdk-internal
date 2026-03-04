//! WASM bindings for the Remote Access Token (RAT) protocol.
//!
//! Exposes `UserClient` from `bw-rat-client` for use in the browser extension,
//! allowing it to act as the trusted device serving credentials.

mod client;
mod proxy;
mod storage;

// RatUserClient is exposed to JS via #[wasm_bindgen], not through Rust exports.
#[allow(unused_imports)]
pub use client::RatUserClient;
