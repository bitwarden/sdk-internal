use bitwarden_api_identity::models::{PasswordPreloginRequestModel, PasswordPreloginResponseModel};
use bitwarden_crypto::Kdf;
use thiserror::Error;

use crate::{ApiError, Client, MissingFieldError, require};

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum PreloginError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

pub(crate) async fn prelogin(client: &Client, email: String) -> Result<Kdf, PreloginError> {
    let request_model = PasswordPreloginRequestModel::new(email);
    let config = client.internal.get_api_configurations().await;
    let result = config
        .identity_client
        .accounts_api()
        .post_password_prelogin(Some(request_model))
        .await
        .map_err(ApiError::from)?;

    Ok(parse_prelogin(result)?)
}

fn parse_prelogin(response: PasswordPreloginResponseModel) -> Result<Kdf, MissingFieldError> {
    use std::num::NonZeroU32;

    use bitwarden_api_identity::models::KdfType;

    let kdf = require!(response.kdf);

    Ok(match kdf {
        KdfType::PBKDF2_SHA256 => Kdf::PBKDF2 {
            iterations: NonZeroU32::new(require!(response.kdf_iterations) as u32)
                .expect("Non-zero number"),
        },
        KdfType::Argon2id => Kdf::Argon2id {
            iterations: NonZeroU32::new(require!(response.kdf_iterations) as u32)
                .expect("Non-zero number"),
            memory: NonZeroU32::new(require!(response.kdf_memory) as u32).expect("Non-zero number"),
            parallelism: NonZeroU32::new(require!(response.kdf_parallelism) as u32)
                .expect("Non-zero number"),
        },
    })
}
