//! WASM bindings for the agent access protocol.
//!
//! Exposes `UserClient` from `ap-client` for use in the browser extension,
//! allowing it to act as the trusted device serving credentials.

mod client;
mod proxy;
mod storage;

// UserClient is exposed to JS via #[wasm_bindgen], not through Rust exports.
#[allow(unused_imports)]
pub use client::UserClient;
// generate_agent_identity is exposed as a standalone wasm_bindgen function.
#[cfg(target_arch = "wasm32")]
#[allow(unused_imports)]
pub use storage::generate_agent_identity;
