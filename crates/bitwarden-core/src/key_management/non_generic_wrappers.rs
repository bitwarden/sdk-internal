//! Structs with generic parameters cannot be moved across FFI bounds (uniffi/wasm).
//! This module contains wrapper structs that hide the generic parameter with instantiated versions.

use std::ops::Deref;

use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use crate::key_management::KeyIds;

/// A non-generic wrapper around `bitwarden-crypto`'s `PasswordProtectedKeyEnvelope`.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct PasswordProtectedKeyEnvelope(
    #[tsify(type = r#"Tagged<string, "PasswordProtectedKeyEnvelope">"#)]
    pub(crate)  bitwarden_crypto::safe::PasswordProtectedKeyEnvelope<KeyIds>,
);

impl Deref for PasswordProtectedKeyEnvelope {
    type Target = bitwarden_crypto::safe::PasswordProtectedKeyEnvelope<KeyIds>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Debug for PasswordProtectedKeyEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
