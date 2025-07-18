use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct SendAccessTokenResponse {
    pub access_token: String,
    pub expires_in: u64, // In seconds
    pub scope: String,
    pub token_type: String,
}
