use serde_repr::{Deserialize_repr, Serialize_repr};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

/// The type of Send, either text or file
#[derive(Clone, Copy, Serialize_repr, Deserialize_repr, Debug, PartialEq)]
#[repr(u8)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub enum SendType {
    /// Text-based send
    Text = 0,
    /// File-based send
    File = 1,
    /// Item-based send
    Item = 2,
}

impl TryFrom<bitwarden_api_api::models::SendType> for SendType {
    type Error = bitwarden_core::MissingFieldError;

    fn try_from(t: bitwarden_api_api::models::SendType) -> Result<Self, Self::Error> {
        Ok(match t {
            bitwarden_api_api::models::SendType::Text => SendType::Text,
            bitwarden_api_api::models::SendType::File => SendType::File,
            bitwarden_api_api::models::SendType::Item => SendType::Item,
            bitwarden_api_api::models::SendType::__Unknown(_) => {
                return Err(bitwarden_core::MissingFieldError("type"));
            }
        })
    }
}

impl From<SendType> for bitwarden_api_api::models::SendType {
    fn from(t: SendType) -> Self {
        match t {
            SendType::Text => bitwarden_api_api::models::SendType::Text,
            SendType::File => bitwarden_api_api::models::SendType::File,
            SendType::Item => bitwarden_api_api::models::SendType::Item,
        }
    }
}
