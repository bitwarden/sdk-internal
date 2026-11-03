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

pub use thread_bound_runner::{CallError, ThreadBoundRunner};

/// Run `future` to completion in the background on the tokio runtime natively.
#[cfg(not(target_arch = "wasm32"))]
pub fn spawn(future: impl std::future::Future<Output = ()> + Send + 'static) {
    tokio::spawn(future);
}

/// Run `future` to completion in the background on the JS event loop in WebAssembly.
#[cfg(target_arch = "wasm32")]
pub fn spawn(future: impl std::future::Future<Output = ()> + 'static) {
    wasm_bindgen_futures::spawn_local(future);
}
