#![doc = include_str!("../README.md")]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
#[cfg(feature = "uniffi")]
mod uniffi_support;

mod error;
pub use error::SendParseError;
mod folder;
pub use folder::{
    MakeSendFolderEntry, MakeSendFolderError, MakeSendFolderFileEntry, MakeSendFolderFileRequest,
    MakeSendFolderFileResult, MakeSendFolderRequest, MakeSendFolderResult,
};
mod send_client;
pub use send_client::{
    SendClient, SendClientExt, SendDecryptError, SendDecryptFileError, SendEncryptError,
    SendEncryptFileError,
};
mod send;
pub use send::{AuthType, Send, SendFileView, SendListView, SendTextView, SendType, SendView};
