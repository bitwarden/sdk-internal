use crate::identity::models::LoginSuccessResponse;
use serde::{Deserialize, Serialize};

/// Common login response model used across different login methods.
#[derive(Debug, Serialize, Deserialize)]
pub enum LoginResponse {
    /// Successful authentication response.
    Authenticated(LoginSuccessResponse),
    // Payload(IdentityTokenPayloadResponse), TBD for secrets manager use
    // Refreshed(LoginRefreshResponse),
    // TwoFactorRequired(Box<IdentityTwoFactorResponse>),
    // TODO: add new device verification response
}
