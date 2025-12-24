use serde::{Deserialize, Serialize};

use crate::identity::models::LoginSuccessResponse;

/// Common login response model used across different login methods.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub enum LoginResponse {
    /// Successful authentication response.
    Authenticated(LoginSuccessResponse),
    // Payload(IdentityTokenPayloadResponse), TBD for secrets manager use
    // Refreshed(LoginRefreshResponse),
    // TwoFactorRequired(Box<IdentityTwoFactorResponse>),
    // TODO: add new device verification response
}
