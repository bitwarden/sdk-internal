use bitwarden_crypto::EncString;
use uuid::Uuid;

use crate::context::{send_file_name_context::SendFileNameContext, send_key_context::SendKeyContext, send_name_context::SendNameContext, send_notes_context::SendNotesContext, send_text_message_context::SendTextMessageContext};

type NameEncString = EncString<SendNameContext>;
type NotesEncString = EncString<SendNotesContext>;
type KeyEncString = EncString<SendKeyContext>;
type TextEncString = EncString<SendTextMessageContext>;
type FileNameEncString = EncString<SendFileNameContext>;

uniffi::ffi_converter_forward!(NameEncString, bitwarden_crypto::UniFfiTag, crate::UniFfiTag);
uniffi::custom_type!(NameEncString, String);
uniffi::custom_type!(NotesEncString, String);
uniffi::custom_type!(KeyEncString, String);
uniffi::custom_type!(TextEncString, String);
uniffi::custom_type!(FileNameEncString, String);


type DateTime = chrono::DateTime<chrono::Utc>;
uniffi::ffi_converter_forward!(DateTime, bitwarden_core::UniFfiTag, crate::UniFfiTag);
uniffi::ffi_converter_forward!(Uuid, bitwarden_core::UniFfiTag, crate::UniFfiTag);
