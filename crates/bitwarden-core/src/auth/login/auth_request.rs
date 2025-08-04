use super::LoginError;
use crate::key_management::master_password::MasterPasswordUnlockData;
use crate::{
    auth::{
        api::{request::AuthRequestTokenRequest, response::IdentityTokenResponse},
        auth_request::new_auth_request,
    },
    client::{LoginMethod, UserLoginMethod},
    key_management::crypto::{AuthRequestMethod, InitUserCryptoMethod, InitUserCryptoRequest},
    require, ApiError, Client,
};
use bitwarden_api_api::{
    apis::auth_requests_api::{auth_requests_id_response_get, auth_requests_post},
    models::{AuthRequestCreateRequestModel, AuthRequestType},
};
use bitwarden_crypto::Kdf;
use uuid::Uuid;

#[allow(missing_docs)]
pub struct NewAuthRequestResponse {
    pub fingerprint: String,
    email: String,
    device_identifier: String,
    auth_request_id: Uuid,
    access_code: String,
    private_key: String,
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
        public_key: auth.public_key,
        device_identifier: device_identifier.clone(),
        access_code: auth.access_code.clone(),
        r#type: AuthRequestType::AuthenticateAndUnlock,
    };

    let res = auth_requests_post(&config.api, Some(req))
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

    let res = auth_requests_id_response_get(
        &config.api,
        auth_req.auth_request_id,
        Some(&auth_req.access_code),
    )
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
        let (kdf, method) = match (res.master_password_hash, r.user_decryption_options) {
            (Some(_), Some(options)) => match options.master_password_unlock {
                Some(master_password) => {
                    let master_password_unlock_data = MasterPasswordUnlockData::process_response(
                        master_password.as_ref().clone(),
                    )?;
                    let kdf = master_password_unlock_data.kdf.clone();
                    let method = AuthRequestMethod::MasterKey {
                        protected_master_key: require!(res.key).parse()?,
                        auth_request_key: master_password_unlock_data.master_key_wrapped_user_key,
                    };
                    (kdf, method)
                }
                None => {
                    // TODO backward compatibility, should be removed in the future and return error
                    let method = AuthRequestMethod::MasterKey {
                        protected_master_key: require!(res.key).parse()?,
                        auth_request_key: require!(r.key).parse()?,
                    };
                    (Kdf::default(), method)
                }
            },
            (None, _) => {
                let method = AuthRequestMethod::UserKey {
                    protected_user_key: require!(res.key).parse()?,
                };
                (Kdf::default(), method)
            }
            (_, _) => return Err(LoginError::InvalidResponse),
        };

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
