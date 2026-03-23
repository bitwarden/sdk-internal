#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

mod create;
pub use create::{CreateSendError, SendAddRequest};
mod edit;
pub use edit::{EditSendError, SendEditRequest};
mod error;
pub use error::SendParseError;
mod get_list;
pub use get_list::GetSendError;
mod send_client;
pub use send_client::{
    SendClient, SendClientExt, SendDecryptError, SendDecryptFileError, SendEncryptError,
    SendEncryptFileError,
};
mod send;
pub use send::{
    AuthType, EmptyEmailListError, Send, SendAuthType, SendFileView, SendId, SendListView,
    SendTextView, SendType, SendView, SendViewType,
};
