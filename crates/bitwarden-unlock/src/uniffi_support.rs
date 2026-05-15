//! UniFFI custom type bridge for types defined in other crates.

// Bring the `safe` module into scope so the macro-generated
// `impl ... for safe::PasswordProtectedKeyEnvelope` resolves.
use bitwarden_crypto::safe;

uniffi::use_remote_type!(bitwarden_crypto::safe::PasswordProtectedKeyEnvelope);
