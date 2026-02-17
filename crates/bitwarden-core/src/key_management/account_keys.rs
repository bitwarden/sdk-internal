use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};

use crate::{MissingFieldError, key_management::SignedSecurityState, require};

/// Error for operations related to Account Keys
#[bitwarden_error(flat)]
#[derive(Debug, thiserror::Error)]
pub enum AccountKeysError {
    /// The private key is missing or malformed.
    #[error("Private key is malformed")]
    PrivateKeyMalformed,
    /// The public key is missing or malformed.
    #[error("Public key is malformed")]
    PublicKeyPairMalformed,
    /// The signature key pair is missing or malformed.
    #[error("Signature is malformed")]
    SignatureKeyPairMalformed,
    /// The security state is missing or malformed.
    #[error("Security state is malformed")]
    SecurityStateMalformed,
    /// The wrapped encryption key or salt fields are missing or KDF data is incomplete
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AccountKeysData {
    pub public_key_encryption_key_pair: PublicKeyEncryptionKeyPairData,
    pub signature_key_pair: Option<SignatureKeyPairData>,
    pub security_state: Option<SecurityStateData>,
}

impl TryFrom<&bitwarden_api_api::models::AccountKeysRequestModel> for AccountKeysData {
    type Error = AccountKeysError;

    fn try_from(
        request: &bitwarden_api_api::models::AccountKeysRequestModel,
    ) -> Result<Self, Self::Error> {
        let public_key_encryption_key_pair = require!(&request.public_key_encryption_key_pair)
            .as_ref()
            .try_into()
            .map_err(|_| AccountKeysError::PublicKeyPairMalformed)?;

        let signature_key_pair = Some(
            require!(&request.signature_key_pair)
                .as_ref()
                .try_into()
                .map_err(|_| AccountKeysError::SignatureKeyPairMalformed)?,
        );

        let security_state = Some(
            require!(&request.security_state)
                .as_ref()
                .try_into()
                .map_err(|_| AccountKeysError::SecurityStateMalformed)?,
        );

        Ok(AccountKeysData {
            public_key_encryption_key_pair,
            signature_key_pair,
            security_state,
        })
    }
}

impl TryFrom<&bitwarden_api_identity::models::AccountKeysRequestModel> for AccountKeysData {
    type Error = AccountKeysError;

    fn try_from(
        request: &bitwarden_api_identity::models::AccountKeysRequestModel,
    ) -> Result<Self, Self::Error> {
        let public_key_encryption_key_pair = require!(&request.public_key_encryption_key_pair)
            .as_ref()
            .try_into()
            .map_err(|_| AccountKeysError::PublicKeyPairMalformed)?;

        let signature_key_pair = Some(
            require!(&request.signature_key_pair)
                .as_ref()
                .try_into()
                .map_err(|_| AccountKeysError::SignatureKeyPairMalformed)?,
        );

        let security_state = Some(
            require!(&request.security_state)
                .as_ref()
                .try_into()
                .map_err(|_| AccountKeysError::SecurityStateMalformed)?,
        );

        Ok(AccountKeysData {
            public_key_encryption_key_pair,
            signature_key_pair,
            security_state,
        })
    }
}

impl From<&AccountKeysData> for bitwarden_api_api::models::AccountKeysRequestModel {
    fn from(data: &AccountKeysData) -> Self {
        Self {
            user_key_encrypted_account_private_key: Some(
                data.public_key_encryption_key_pair
                    .wrapped_private_key
                    .to_owned(),
            ),
            account_public_key: Some(data.public_key_encryption_key_pair.public_key.to_owned()),
            public_key_encryption_key_pair: Some(Box::new(
                (&data.public_key_encryption_key_pair).into(),
            )),
            signature_key_pair: data.signature_key_pair.as_ref().map(|v| Box::new(v.into())),
            security_state: data.security_state.as_ref().map(|v| Box::new(v.into())),
        }
    }
}

impl From<&AccountKeysData> for bitwarden_api_identity::models::AccountKeysRequestModel {
    fn from(data: &AccountKeysData) -> Self {
        Self {
            user_key_encrypted_account_private_key: Some(
                data.public_key_encryption_key_pair
                    .wrapped_private_key
                    .to_owned(),
            ),
            account_public_key: Some(data.public_key_encryption_key_pair.public_key.to_owned()),
            public_key_encryption_key_pair: Some(Box::new(
                (&data.public_key_encryption_key_pair).into(),
            )),
            signature_key_pair: data.signature_key_pair.as_ref().map(|v| Box::new(v.into())),
            security_state: data.security_state.as_ref().map(|v| Box::new(v.into())),
        }
    }
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicKeyEncryptionKeyPairData {
    pub wrapped_private_key: String,
    pub public_key: String,
    pub signed_public_key: Option<String>,
}

impl TryFrom<&bitwarden_api_api::models::PublicKeyEncryptionKeyPairRequestModel>
    for PublicKeyEncryptionKeyPairData
{
    type Error = AccountKeysError;

    fn try_from(
        request: &bitwarden_api_api::models::PublicKeyEncryptionKeyPairRequestModel,
    ) -> Result<Self, Self::Error> {
        Ok(PublicKeyEncryptionKeyPairData {
            wrapped_private_key: require!(&request.wrapped_private_key).clone(),
            public_key: require!(&request.public_key).clone(),
            signed_public_key: request.signed_public_key.clone(),
        })
    }
}

impl TryFrom<&bitwarden_api_identity::models::PublicKeyEncryptionKeyPairRequestModel>
    for PublicKeyEncryptionKeyPairData
{
    type Error = AccountKeysError;

    fn try_from(
        request: &bitwarden_api_identity::models::PublicKeyEncryptionKeyPairRequestModel,
    ) -> Result<Self, Self::Error> {
        Ok(PublicKeyEncryptionKeyPairData {
            wrapped_private_key: require!(&request.wrapped_private_key).clone(),
            public_key: require!(&request.public_key).clone(),
            signed_public_key: request.signed_public_key.clone(),
        })
    }
}

impl From<&PublicKeyEncryptionKeyPairData>
    for bitwarden_api_api::models::PublicKeyEncryptionKeyPairRequestModel
{
    fn from(data: &PublicKeyEncryptionKeyPairData) -> Self {
        Self {
            wrapped_private_key: Some(data.wrapped_private_key.to_owned()),
            public_key: Some(data.public_key.to_owned()),
            signed_public_key: data.signed_public_key.to_owned(),
        }
    }
}

impl From<&PublicKeyEncryptionKeyPairData>
    for bitwarden_api_identity::models::PublicKeyEncryptionKeyPairRequestModel
{
    fn from(data: &PublicKeyEncryptionKeyPairData) -> Self {
        Self {
            wrapped_private_key: Some(data.wrapped_private_key.to_owned()),
            public_key: Some(data.public_key.to_owned()),
            signed_public_key: data.signed_public_key.to_owned(),
        }
    }
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignatureKeyPairData {
    pub signature_algorithm: String,
    pub wrapped_signing_key: String,
    pub verifying_key: String,
}

impl TryFrom<&bitwarden_api_api::models::SignatureKeyPairRequestModel> for SignatureKeyPairData {
    type Error = AccountKeysError;

    fn try_from(
        request: &bitwarden_api_api::models::SignatureKeyPairRequestModel,
    ) -> Result<Self, Self::Error> {
        Ok(SignatureKeyPairData {
            signature_algorithm: require!(&request.signature_algorithm).clone(),
            wrapped_signing_key: require!(&request.wrapped_signing_key).clone(),
            verifying_key: require!(&request.verifying_key).clone(),
        })
    }
}

impl TryFrom<&bitwarden_api_identity::models::SignatureKeyPairRequestModel>
    for SignatureKeyPairData
{
    type Error = AccountKeysError;

    fn try_from(
        request: &bitwarden_api_identity::models::SignatureKeyPairRequestModel,
    ) -> Result<Self, Self::Error> {
        Ok(SignatureKeyPairData {
            signature_algorithm: require!(&request.signature_algorithm).clone(),
            wrapped_signing_key: require!(&request.wrapped_signing_key).clone(),
            verifying_key: require!(&request.verifying_key).clone(),
        })
    }
}

impl From<&SignatureKeyPairData> for bitwarden_api_api::models::SignatureKeyPairRequestModel {
    fn from(data: &SignatureKeyPairData) -> Self {
        Self {
            signature_algorithm: Some(data.signature_algorithm.to_owned()),
            wrapped_signing_key: Some(data.wrapped_signing_key.to_owned()),
            verifying_key: Some(data.verifying_key.to_owned()),
        }
    }
}

impl From<&SignatureKeyPairData> for bitwarden_api_identity::models::SignatureKeyPairRequestModel {
    fn from(data: &SignatureKeyPairData) -> Self {
        Self {
            signature_algorithm: Some(data.signature_algorithm.to_owned()),
            wrapped_signing_key: Some(data.wrapped_signing_key.to_owned()),
            verifying_key: Some(data.verifying_key.to_owned()),
        }
    }
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecurityStateData {
    pub security_state: SignedSecurityState,
    pub security_version: i32,
}

impl TryFrom<&bitwarden_api_api::models::SecurityStateModel> for SecurityStateData {
    type Error = AccountKeysError;

    fn try_from(
        request: &bitwarden_api_api::models::SecurityStateModel,
    ) -> Result<Self, Self::Error> {
        Ok(SecurityStateData {
            security_state: require!(&request.security_state)
                .clone()
                .parse()
                .map_err(|_| AccountKeysError::SecurityStateMalformed)?,
            security_version: request.security_version,
        })
    }
}

impl TryFrom<&bitwarden_api_identity::models::SecurityStateModel> for SecurityStateData {
    type Error = AccountKeysError;

    fn try_from(
        request: &bitwarden_api_identity::models::SecurityStateModel,
    ) -> Result<Self, Self::Error> {
        Ok(SecurityStateData {
            security_state: require!(&request.security_state)
                .clone()
                .parse()
                .map_err(|_| AccountKeysError::SecurityStateMalformed)?,
            security_version: request.security_version,
        })
    }
}

impl From<&SecurityStateData> for bitwarden_api_api::models::SecurityStateModel {
    fn from(data: &SecurityStateData) -> Self {
        Self {
            security_state: Some(data.security_state.to_owned().into()),
            security_version: data.security_version,
        }
    }
}

impl From<&SecurityStateData> for bitwarden_api_identity::models::SecurityStateModel {
    fn from(data: &SecurityStateData) -> Self {
        Self {
            security_state: Some(data.security_state.to_owned().into()),
            security_version: data.security_version,
        }
    }
}
