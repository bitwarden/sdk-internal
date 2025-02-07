#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

mod error;
pub use error::SendParseError;
mod send_client;
pub use send_client::{
    SendClient, SendClientExt, SendDecryptError, SendDecryptFileError, SendEncryptError,
    SendEncryptFileError,
};
mod send;
pub use send::{Send, SendListView, SendView};
