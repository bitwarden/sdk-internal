use bitwarden_api_identity::models::{PreloginRequestModel, PreloginResponseModel};
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
    let request_model = PreloginRequestModel::new(email);
    let config = client.internal.get_api_configurations().await;
    let result = config
        .identity_client
        .accounts_api()
        .post_prelogin(Some(request_model))
        .await
        .map_err(ApiError::from)?;

    Ok(parse_prelogin(result)?)
}

fn parse_prelogin(response: PreloginResponseModel) -> Result<Kdf, MissingFieldError> {
    use std::num::NonZeroU32;

    use bitwarden_api_identity::models::KdfType;
    use bitwarden_crypto::{
        default_argon2_iterations, default_argon2_memory, default_argon2_parallelism,
        default_pbkdf2_iterations,
    };

    let kdf = require!(response.kdf);

    Ok(match kdf {
        KdfType::PBKDF2_SHA256 => Kdf::PBKDF2 {
            iterations: response
                .kdf_iterations
                .and_then(|e| NonZeroU32::new(e as u32))
                .unwrap_or_else(default_pbkdf2_iterations),
        },
        KdfType::Argon2id => Kdf::Argon2id {
            iterations: response
                .kdf_iterations
                .and_then(|e| NonZeroU32::new(e as u32))
                .unwrap_or_else(default_argon2_iterations),
            memory: response
                .kdf_memory
                .and_then(|e| NonZeroU32::new(e as u32))
                .unwrap_or_else(default_argon2_memory),
            parallelism: response
                .kdf_parallelism
                .and_then(|e| NonZeroU32::new(e as u32))
                .unwrap_or_else(default_argon2_parallelism),
        },
    })
}
