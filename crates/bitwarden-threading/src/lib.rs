#![doc = include_str!("../README.md")]

#[cfg(all(target_arch = "wasm32", not(feature = "wasm")))]
compile_error!(
    "The `wasm` feature must be enabled to use the `bitwarden-ipc` crate in a WebAssembly environment."
);

#[allow(missing_docs)]
pub mod cancellation_token;
mod thread_bound_runner;
#[allow(missing_docs)]
pub mod time;

pub use thread_bound_runner::ThreadBoundRunner;
