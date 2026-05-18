use bitwarden_crypto::{SymmetricCryptoKey, safe};
use uuid::Uuid;

// Forward the type definitions to the main bitwarden crate
type DateTime = jiff::Timestamp;
uniffi::use_remote_type!(bitwarden_core::DateTime);

uniffi::use_remote_type!(bitwarden_core::Uuid);

uniffi::use_remote_type!(bitwarden_crypto::safe::PasswordProtectedKeyEnvelope);

uniffi::use_remote_type!(bitwarden_crypto::SymmetricCryptoKey);
