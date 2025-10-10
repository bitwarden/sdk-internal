use bitwarden_api_api::models::{AuthRequestCreateRequestModel, AuthRequestType};
use bitwarden_crypto::Kdf;
use bitwarden_encoding::B64;
use uuid::Uuid;

use super::LoginError;
use crate::{
    ApiError, Client,
    auth::{
        api::{request::AuthRequestTokenRequest, response::IdentityTokenResponse},
        auth_request::new_auth_request,
    },
    client::{LoginMethod, UserLoginMethod},
    key_management::crypto::{AuthRequestMethod, InitUserCryptoMethod, InitUserCryptoRequest},
    require,
};

#[allow(missing_docs)]
pub struct NewAuthRequestResponse {
    pub fingerprint: String,
    email: String,
    device_identifier: String,
    auth_request_id: Uuid,
    access_code: String,
    private_key: B64,
}

pub(crate) async fn send_new_auth_request(
    client: &Client,
    email: String,
    device_identifier: String,
) -> Result<NewAuthRequestResponse, LoginError> {
    let config = client.internal.get_api_configurations().await;

    let auth = new_auth_request(&email)?;

    let req = AuthRequestCreateRequestModel {
        email: email.clone(),
        public_key: auth.public_key.to_string(),
        device_identifier: device_identifier.clone(),
        access_code: auth.access_code.clone(),
        r#type: AuthRequestType::AuthenticateAndUnlock,
    };

    let res = config
        .api_client
        .auth_requests_api()
        .post(Some(req))
        .await
        .map_err(ApiError::from)?;

    Ok(NewAuthRequestResponse {
        fingerprint: auth.fingerprint,
        email,
        device_identifier,
        auth_request_id: require!(res.id),
        access_code: auth.access_code,
        private_key: auth.private_key,
    })
}

pub(crate) async fn complete_auth_request(
    client: &Client,
    auth_req: NewAuthRequestResponse,
) -> Result<(), LoginError> {
    let config = client.internal.get_api_configurations().await;
    let res = config
        .api_client
        .auth_requests_api()
        .get_response(auth_req.auth_request_id, Some(&auth_req.access_code))
        .await
        .map_err(ApiError::from)?;

    let approved = res.request_approved.unwrap_or(false);

    if !approved {
        return Err(LoginError::AuthRequestNotApproved);
    }

    let response = AuthRequestTokenRequest::new(
        &auth_req.email,
        &auth_req.auth_request_id,
        &auth_req.access_code,
        config.device_type,
        &auth_req.device_identifier,
    )
    .send(&config)
    .await?;

    if let IdentityTokenResponse::Authenticated(r) = response {
        let kdf = Kdf::default();

        client.internal.set_tokens(
            r.access_token.clone(),
            r.refresh_token.clone(),
            r.expires_in,
        );
        client
            .internal
            .set_login_method(LoginMethod::User(UserLoginMethod::Username {
                client_id: "web".to_owned(),
                email: auth_req.email.to_owned(),
                kdf: kdf.clone(),
            }));

        let method = match res.master_password_hash {
            Some(_) => AuthRequestMethod::MasterKey {
                protected_master_key: require!(res.key).parse()?,
                auth_request_key: require!(r.key).parse()?,
            },
            None => AuthRequestMethod::UserKey {
                protected_user_key: require!(res.key).parse()?,
            },
        };

        client
            .crypto()
            .initialize_user_crypto(InitUserCryptoRequest {
                user_id: None,
                kdf_params: kdf,
                email: auth_req.email,
                private_key: require!(r.private_key).parse()?,
                signing_key: None,
                security_state: None,
                method: InitUserCryptoMethod::AuthRequest {
                    request_private_key: auth_req.private_key,
                    method,
                },
            })
            .await?;

        Ok(())
    } else {
        Err(LoginError::AuthenticationFailed)
    }
}
