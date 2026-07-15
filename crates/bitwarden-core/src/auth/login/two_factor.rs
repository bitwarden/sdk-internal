use bitwarden_api_api::models::TwoFactorEmailLoginRequestModel;
use bitwarden_crypto::HashPurpose;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use thiserror::Error;

use crate::{
    ApiError, Client,
    auth::{login::PreloginError, password::determine_password_hash},
};

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TwoFactorEmailRequest {
    /// User Password
    pub password: String,
    /// User email
    pub email: String,
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum TwoFactorEmailError {
    #[error(transparent)]
    Prelogin(#[from] PreloginError),
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
}

pub(crate) async fn send_two_factor_email(
    client: &Client,
    input: &TwoFactorEmailRequest,
) -> Result<(), TwoFactorEmailError> {
    // TODO: This should be resolved from the client
    let kdf = client.auth().prelogin(input.email.clone()).await?;

    let password_hash = determine_password_hash(
        &input.email,
        &kdf,
        &input.password,
        HashPurpose::ServerAuthorization,
    )?;

    let config = client.internal.get_api_configurations();
    config
        .api_client
        .two_factor_api()
        .send_email_login(Some(TwoFactorEmailLoginRequestModel {
            master_password_hash: Some(password_hash.to_string()),
            otp: None,
            auth_request_access_code: None,
            secret: None,
            email: input.email.to_owned(),
            auth_request_id: None,
            sso_email2_fa_session_token: None,
        }))
        .await
        .map_err(ApiError::from)?;

    Ok(())
}

#[allow(missing_docs)]
#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, JsonSchema, Clone)]
#[repr(u8)]
pub enum TwoFactorProvider {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    Yubikey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
    WebAuthn = 7,
}

#[allow(missing_docs)]
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TwoFactorRequest {
    /// Two-factor Token
    pub token: String,
    /// Two-factor provider
    pub provider: TwoFactorProvider,
    /// Two-factor remember
    pub remember: bool,
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::ResponseContent;
    use bitwarden_api_identity::models::KdfType;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;
    use crate::{ClientSettings, DeviceType};

    fn settings_for(server: &MockServer) -> ClientSettings {
        ClientSettings {
            identity_url: format!("http://{}", server.address()),
            api_url: format!("http://{}", server.address()),
            user_agent: "two-factor-tests".to_string(),
            device_type: DeviceType::SDK,
            device_identifier: None,
            bitwarden_client_version: None,
            bitwarden_package_type: None,
        }
    }

    async fn mock_prelogin_success(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/accounts/prelogin/password"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "kdf": KdfType::PBKDF2_SHA256.as_i64(),
                "kdfIterations": 600_000,
            })))
            .mount(server)
            .await;
    }

    fn test_input() -> TwoFactorEmailRequest {
        TwoFactorEmailRequest {
            password: "test123".to_string(),
            email: "test@bitwarden.com".to_string(),
        }
    }

    #[tokio::test]
    async fn send_two_factor_email_success() {
        let server = MockServer::start().await;
        mock_prelogin_success(&server).await;
        Mock::given(method("POST"))
            .and(path("/two-factor/send-email-login"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new(Some(settings_for(&server)));

        let result = send_two_factor_email(&client, &test_input()).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn send_two_factor_email_api_error() {
        let server = MockServer::start().await;
        mock_prelogin_success(&server).await;
        Mock::given(method("POST"))
            .and(path("/two-factor/send-email-login"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        let client = Client::new(Some(settings_for(&server)));

        let result = send_two_factor_email(&client, &test_input()).await;

        match result {
            Err(TwoFactorEmailError::Api(ApiError::Response(ResponseContent {
                status,
                message: _,
            }))) => {
                assert_eq!(status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
            }
            other => panic!("Expected Api Response error, got {:?}", other),
        }
    }
}
