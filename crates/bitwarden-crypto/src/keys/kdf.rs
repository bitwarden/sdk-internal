use std::num::NonZeroU32;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify_next::Tsify;

/// Key Derivation Function for Bitwarden Account
///
/// In Bitwarden accounts can use multiple KDFs to derive their master key from their password. This
/// Enum represents all the possible KDFs.
#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum Kdf {
    PBKDF2 {
        iterations: NonZeroU32,
    },
    Argon2id {
        iterations: NonZeroU32,
        memory: NonZeroU32,
        parallelism: NonZeroU32,
    },
}

impl Default for Kdf {
    /// Default KDF for new accounts.
    fn default() -> Self {
        Kdf::PBKDF2 {
            iterations: default_pbkdf2_iterations(),
        }
    }
}

/// Default PBKDF2 iterations
pub fn default_pbkdf2_iterations() -> NonZeroU32 {
    NonZeroU32::new(600_000).expect("Non-zero number")
}
/// Default Argon2 iterations
pub fn default_argon2_iterations() -> NonZeroU32 {
    NonZeroU32::new(3).expect("Non-zero number")
}
/// Default Argon2 memory
pub fn default_argon2_memory() -> NonZeroU32 {
    NonZeroU32::new(64).expect("Non-zero number")
}
/// Default Argon2 parallelism
pub fn default_argon2_parallelism() -> NonZeroU32 {
    NonZeroU32::new(4).expect("Non-zero number")
}
