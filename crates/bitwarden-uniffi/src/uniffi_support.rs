use bitwarden_crypto::{EncString, UnauthenticatedSharedKey};
use uuid::Uuid;

// Forward the type definitions to the main bitwarden crate
type DateTime = chrono::DateTime<chrono::Utc>;
uniffi::ffi_converter_forward!(DateTime, bitwarden_core::UniFfiTag, crate::UniFfiTag);
uniffi::ffi_converter_forward!(EncString, bitwarden_core::UniFfiTag, crate::UniFfiTag);
uniffi::ffi_converter_forward!(
    UnauthenticatedSharedKey,
    bitwarden_core::UniFfiTag,
    crate::UniFfiTag
);
uniffi::ffi_converter_forward!(Uuid, bitwarden_core::UniFfiTag, crate::UniFfiTag);
