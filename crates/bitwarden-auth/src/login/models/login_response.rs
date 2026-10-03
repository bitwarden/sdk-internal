use serde::{Deserialize, Serialize};

use crate::login::models::LoginSuccessResponse;

/// Common login response model used across different login methods.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[bitwarden_ffi::wasm_record]
pub enum LoginResponse {
    /// Successful authentication response.
    Authenticated(LoginSuccessResponse),
    // Payload(IdentityTokenPayloadResponse), TBD for secrets manager use
    // Refreshed(LoginRefreshResponse),
    // TwoFactorRequired(Box<IdentityTwoFactorResponse>),
    // TODO: add new device verification response
}
