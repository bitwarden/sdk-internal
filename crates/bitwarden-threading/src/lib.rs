#[cfg(all(target_arch = "wasm32", not(feature = "wasm")))]
compile_error!(
    "The `wasm` feature must be enabled to use the `bitwarden-ipc` crate in a WebAssembly environment."
);

pub mod cancellation_token;
mod thread_bound_runner;
pub mod time;

pub use thread_bound_runner::ThreadBoundRunner;
