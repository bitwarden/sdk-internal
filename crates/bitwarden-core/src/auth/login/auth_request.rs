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
    key_management::{
        UserDecryptionData,
        account_cryptographic_state::WrappedUserAccountCryptographicState,
        crypto::{AuthRequestMethod, InitUserCryptoMethod, InitUserCryptoRequest},
    },
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
        client.internal.set_tokens(
            r.access_token.clone(),
            r.refresh_token.clone(),
            r.expires_in,
        );

        let method = match res.master_password_hash {
            Some(_) => AuthRequestMethod::MasterKey {
                protected_master_key: require!(res.key).parse()?,
                auth_request_key: require!(r.key).parse()?,
            },
            None => AuthRequestMethod::UserKey {
                protected_user_key: require!(res.key).parse()?,
            },
        };

        let master_password_unlock = r
            .user_decryption_options
            .as_ref()
            .map(UserDecryptionData::try_from)
            .transpose()?
            .and_then(|user_decryption| user_decryption.master_password_unlock);
        let kdf = master_password_unlock
            .as_ref()
            .map(|mpu| mpu.kdf.clone())
            .unwrap_or_else(Kdf::default);
        let salt = master_password_unlock
            .as_ref()
            .map(|mpu| mpu.salt.clone())
            .unwrap_or_else(|| auth_req.email.clone());

        client
            .crypto()
            .initialize_user_crypto(InitUserCryptoRequest {
                user_id: None,
                kdf_params: kdf,
                email: salt,
                account_cryptographic_state: WrappedUserAccountCryptographicState::V1 {
                    private_key: require!(r.private_key).parse()?,
                },
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
