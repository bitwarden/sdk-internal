use crate::auth::send_access::responses::SendAccessTokenResponse;

/// A send access token which can be used to access a send.
pub struct SendAccessToken {
    /// The actual token string.
    pub token: String,
    /// The timestamp in milliseconds when the token expires.
    pub expires_at: i64,
}

// Traits
impl From<SendAccessTokenResponse> for SendAccessToken {
    fn from(response: SendAccessTokenResponse) -> Self {
        // We want to convert the expires_in from seconds to a millisecond timestamp to have a concrete time the token will expire
        // as it is easier to build logic around a concrete time rather than a duration.
        let expires_at =
            chrono::Utc::now().timestamp_millis() + (response.expires_in * 1000) as i64;

        SendAccessToken {
            token: response.access_token,
            expires_at,
        }
    }
}
