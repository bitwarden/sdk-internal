use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
/// The server response for successful send access token request.
pub(crate) struct SendAccessTokenApiSuccessResponse {
    /// The access token string.
    pub(crate) access_token: String,
    /// The duration in seconds until the token expires.
    pub(crate) expires_in: u64,
    /// The scope of the access token.
    /// RFC: <https://datatracker.ietf.org/doc/html/rfc6749#section-3.3>
    pub(crate) scope: String,
    /// The type of the token.
    /// This will be "Bearer" for send access tokens.
    /// More information can be found in the OAuth 2.0 authZ framework RFC:
    /// <https://datatracker.ietf.org/doc/html/rfc6749#section-7.1>
    pub(crate) token_type: String,
}
