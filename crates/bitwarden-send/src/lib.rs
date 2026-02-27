#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

mod create;
mod edit;
mod error;
pub use error::SendParseError;
mod get_list;
mod send_client;
pub use send_client::{
    SendClient, SendClientExt, SendDecryptError, SendDecryptFileError, SendEncryptError,
    SendEncryptFileError,
};
mod send;
pub use send::{AuthType, Send, SendListView, SendTextView, SendFileView, SendType, SendView};
