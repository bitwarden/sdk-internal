use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum KeyRotationMethod {
    /// Master password user, key rotation without a password change.
    Password { password: String },
    /// Key connector user, key rotation without a password change.
    /// NOTE: This is not yet implemented and will return a
    /// RotateUserKeysError::UnimplementedKeyRotationMethod error if used.
    KeyConnector,
    /// TDE user, key rotation without a password change.
    /// NOTE: This is not yet implemented and will return a
    /// RotateUserKeysError::UnimplementedKeyRotationMethod error if used.
    Tde,
}
