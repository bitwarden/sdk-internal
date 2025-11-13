use crate::identity::IdentityClient;

///
#[derive(Serialize, Debug)]
struct PasswordLoginRequestPayload {
    // Common user token request payload
    #[serde(flatten)]
    user_token_request_payload: UserTokenRequestPayload,

    /// Bitwarden user email address
    pub email: String,
    /// Bitwarden user master password hash
    pub master_password_hash: String,
}

impl IdentityClient {
    pub async fn login_via_password(&self, request: PasswordLoginRequest) {
        // Implementation goes here
    }
}
