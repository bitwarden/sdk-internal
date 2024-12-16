pub mod error;
pub mod generator;
pub mod import;

use serde::{Deserialize, Serialize};

#[cfg(feature = "wasm")]
use tsify_next::Tsify;

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct SshKey {
    pub private_key: String,
    pub public_key: String,
    pub key_fingerprint: String,
}
