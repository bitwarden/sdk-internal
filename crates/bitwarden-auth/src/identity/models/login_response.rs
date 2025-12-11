use crate::identity::models::LoginSuccessResponse;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum LoginResponse {
    Authenticated(LoginSuccessResponse),
    // Payload(IdentityTokenPayloadResponse), TBD for secrets manager use
    // Refreshed(LoginRefreshResponse),
    // TwoFactorRequired(Box<IdentityTwoFactorResponse>),
    // TODO: add new device verification response
}
