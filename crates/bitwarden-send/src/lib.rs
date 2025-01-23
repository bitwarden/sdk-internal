#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

mod context;
mod error;
pub use error::SendParseError;
mod send_client;
pub use send_client::{SendClient, SendClientExt};
mod send;
mod send_context;
pub use send::{Send, SendListView, SendView};
