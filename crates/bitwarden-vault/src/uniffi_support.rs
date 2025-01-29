use bitwarden_crypto::{EncString, NoContext};
use uuid::Uuid;

uniffi::ffi_converter_forward!(EncString<NoContext>, bitwarden_crypto::UniFfiTag, crate::UniFfiTag);

type DateTime = chrono::DateTime<chrono::Utc>;
uniffi::ffi_converter_forward!(DateTime, bitwarden_core::UniFfiTag, crate::UniFfiTag);
uniffi::ffi_converter_forward!(Uuid, bitwarden_core::UniFfiTag, crate::UniFfiTag);
