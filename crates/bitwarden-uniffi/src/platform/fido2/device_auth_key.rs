use std::sync::Arc;

use bitwarden_core::platform::SecretVerificationRequest;
use bitwarden_crypto::Kdf;
use bitwarden_fido::{
    DeviceAuthKeyError as BitDeviceAuthKeyError, DeviceAuthKeyGetAssertionResult,
    DeviceAuthKeyMetadata, DeviceAuthKeyRecord, GetAssertionRequest,
};

use super::UniffiTraitBridge;
use crate::error::{Error, Result};

#[derive(uniffi::Object)]
pub struct ClientDeviceAuthKeyAuthenticator {
    pub(super) client: bitwarden_fido::ClientFido2,
    pub(super) store: Arc<dyn DeviceAuthKeyStore>,
}

#[uniffi::export(async_runtime = "tokio")]
impl ClientDeviceAuthKeyAuthenticator {
    /// Create a device auth key by registering an unlock passkey and PRF keyset with the server.
    /// The passkey private key and metadata will be stored on the device using the provided trait
    /// implementation.
    pub async fn create_device_auth_key(
        &self,
        client_name: String,
        web_vault_url: String,
        email: String,
        secret_verification_request: SecretVerificationRequest,
        kdf: Kdf,
    ) -> Result<()> {
        let mut store = UniffiTraitBridge(self.store.as_ref());
        let mut authenticator = self.client.create_device_key_authenticator(&mut store);
        authenticator
            .create_device_auth_key(
                client_name,
                web_vault_url,
                email,
                secret_verification_request,
                kdf,
            )
            .await
            .map_err(Error::DeviceAuthKey)
    }

    /// Uses a device auth key to respond to the provided WebAuthn assertion request.
    /// Satisfy the given FIDO assertion `request` using the device auth key.
    /// The device auth key will be looked up from the
    /// [ClientDeviceAuthKeyAuthenticator::store] provided in the initializer.
    async fn assert_device_auth_key(
        &self,
        request: GetAssertionRequest,
    ) -> Result<DeviceAuthKeyGetAssertionResult> {
        let mut store = UniffiTraitBridge(self.store.as_ref());
        let mut authenticator = self.client.create_device_key_authenticator(&mut store);
        authenticator
            .assert_device_auth_key(request)
            .await
            .map_err(Error::DeviceAuthKey)
    }

    /// Deletes a device auth key and unregisters it from the server.
    async fn unregister_device_auth_key(
        &self,
        email: String,
        secret_verification_request: SecretVerificationRequest,
        kdf: Kdf,
    ) -> Result<()> {
        let mut store = UniffiTraitBridge(self.store.as_ref());
        let mut authenticator = self.client.create_device_key_authenticator(&mut store);
        authenticator
            .unregister_device_auth_key(email, secret_verification_request, kdf)
            .await
            .map_err(Error::DeviceAuthKey)
    }
}

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait DeviceAuthKeyStore: Send + Sync {
    async fn create_record(
        &self,
        record: DeviceAuthKeyRecord,
    ) -> Result<(), DeviceAuthKeyCallbackError>;
    async fn create_metadata(
        &self,
        metadata: DeviceAuthKeyMetadata,
    ) -> Result<(), DeviceAuthKeyCallbackError>;
    async fn get_metadata(
        &self,
    ) -> Result<Option<DeviceAuthKeyMetadata>, DeviceAuthKeyCallbackError>;
    async fn get_record(&self) -> Result<Option<DeviceAuthKeyRecord>, DeviceAuthKeyCallbackError>;
    async fn delete_record_and_metadata(&self) -> Result<(), DeviceAuthKeyCallbackError>;
}

/// Copy of the DeviceAuthKeyStore trait for UniFFI purposes.
/// See note on [UniffiTraitBridge].
#[async_trait::async_trait]
impl bitwarden_fido::DeviceAuthKeyStore for UniffiTraitBridge<&dyn DeviceAuthKeyStore> {
    async fn create_record(
        &mut self,
        record: DeviceAuthKeyRecord,
    ) -> Result<(), BitDeviceAuthKeyError> {
        self.0.create_record(record).await.map_err(Into::into)
    }

    async fn create_metadata(
        &mut self,
        metadata: DeviceAuthKeyMetadata,
    ) -> Result<(), BitDeviceAuthKeyError> {
        self.0.create_metadata(metadata).await.map_err(Into::into)
    }

    async fn get_metadata(&self) -> Result<Option<DeviceAuthKeyMetadata>, BitDeviceAuthKeyError> {
        self.0.get_metadata().await.map_err(Into::into)
    }

    async fn get_record(&self) -> Result<Option<DeviceAuthKeyRecord>, BitDeviceAuthKeyError> {
        self.0.get_record().await.map_err(Into::into)
    }

    async fn delete_record_and_metadata(&mut self) -> Result<(), BitDeviceAuthKeyError> {
        self.0
            .delete_record_and_metadata()
            .await
            .map_err(Into::into)
    }
}

/// Errors related to processing the device auth key.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum DeviceAuthKeyCallbackError {
    /// Authenticator failed to produce a valid response.
    #[error("The authenticator failed to produce a valid response")]
    AuthenticatorFailure,

    /// Failed to convert between Rust types.
    #[error("Failed to convert between Rust types")]
    Conversion,

    /// Credential excluded.
    #[error("The existing device auth key is already registered on the server.")]
    CredentialExcluded,

    /// The record identifier stored in metadata is not a valid UUID.
    #[error("The record identifier is not a valid UUID")]
    InvalidRecordIdentifier,

    /// Invalid Web Vault URL specified.
    #[error("Invalid Web Vault URL specified")]
    InvalidWebVaultUrl,

    /// No device auth key exists on this device.
    #[error("No device auth key exists on this device")]
    MissingDeviceAuthKey,

    /// Failed to unregister device auth key from server.
    #[error("Failed to unregister device auth key from server")]
    UnregisterFailure,

    /// Failed to de-/serialize COSE key data.
    #[error("Failed to de-/serialize COSE key data")]
    InvalidCoseKey,

    /// An invalid public key credential descriptor was passed in the allow list.
    #[error("An invalid public key credential descriptor was passed in the allow list")]
    InvalidPublicKeyCredentialDescriptor,

    /// A master password hash could not be generated for the given master password.
    #[error("A master password hash could not be generated for the given master password")]
    MasterPasswordHash,

    /// Credential ID was not returned in the response and was not passed in the request.
    #[error(
        "No credential ID was returned in the response nor was a single credential ID passed in the request"
    )]
    MissingCredentialId,

    /// No HMAC secret was returned with the credential.
    #[error("No HMAC secret was returned with the credential")]
    MissingHmacSecret,

    /// User handle was not returned in the response.
    #[error("User handle was not returned in the response")]
    MissingUserHandle,

    /// Feature is not yet implemented.
    #[error("Feature is not yet implemented")]
    NotImplemented,

    /// Failed to retrieve the registration options from the server.
    #[error("Failed to retrieve the registration options from the server")]
    RetrieveRegistrationOptionsFailure,

    /// Failed to generate rotateable key set from PRF output.
    #[error("Failed to generate rotateable key set from PRF output")]
    PrfFailure,

    /// Failed to submit registration request to the server.
    #[error("Failed to submit registration request to the server")]
    SubmitRegistrationFailure,

    /// User cancelled the operation.
    #[error("User cancelled the operation")]
    UserCancelled,

    /// An unknown error occurred.
    #[error("An unknown error occurred")]
    Unknown {
        /// Reason for the error.
        reason: String,
    },
}

// Need to implement this From<> impl in order to handle unexpected callback errors.  See the
// following page in the Uniffi user guide:
// <https://mozilla.github.io/uniffi-rs/foreign_traits.html#error-handling>
impl From<uniffi::UnexpectedUniFFICallbackError> for DeviceAuthKeyCallbackError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unknown { reason: e.reason }
    }
}

impl From<DeviceAuthKeyCallbackError> for BitDeviceAuthKeyError {
    fn from(val: DeviceAuthKeyCallbackError) -> Self {
        match val {
            DeviceAuthKeyCallbackError::AuthenticatorFailure => Self::AuthenticatorFailure,
            DeviceAuthKeyCallbackError::Conversion => Self::Conversion,
            DeviceAuthKeyCallbackError::CredentialExcluded => Self::CredentialExcluded,
            DeviceAuthKeyCallbackError::InvalidRecordIdentifier => Self::InvalidRecordIdentifier,
            DeviceAuthKeyCallbackError::InvalidWebVaultUrl => Self::InvalidWebVaultUrl,
            DeviceAuthKeyCallbackError::MissingDeviceAuthKey => Self::MissingDeviceAuthKey,
            DeviceAuthKeyCallbackError::UnregisterFailure => Self::UnregisterFailure,
            DeviceAuthKeyCallbackError::InvalidCoseKey => Self::InvalidCoseKey,
            DeviceAuthKeyCallbackError::InvalidPublicKeyCredentialDescriptor => {
                Self::InvalidPublicKeyCredentialDescriptor
            }
            DeviceAuthKeyCallbackError::MasterPasswordHash => Self::MasterPasswordHash,
            DeviceAuthKeyCallbackError::MissingCredentialId => Self::MissingCredentialId,
            DeviceAuthKeyCallbackError::MissingHmacSecret => Self::MissingHmacSecret,
            DeviceAuthKeyCallbackError::MissingUserHandle => Self::MissingUserHandle,
            DeviceAuthKeyCallbackError::NotImplemented => Self::NotImplemented,
            DeviceAuthKeyCallbackError::RetrieveRegistrationOptionsFailure => {
                Self::RetrieveRegistrationOptionsFailure
            }
            DeviceAuthKeyCallbackError::PrfFailure => Self::PrfFailure,
            DeviceAuthKeyCallbackError::SubmitRegistrationFailure => {
                Self::SubmitRegistrationFailure
            }
            DeviceAuthKeyCallbackError::UserCancelled => Self::UserCancelled,
            DeviceAuthKeyCallbackError::Unknown { reason } => Self::Unknown { reason },
        }
    }
}

impl From<BitDeviceAuthKeyError> for DeviceAuthKeyCallbackError {
    fn from(val: BitDeviceAuthKeyError) -> Self {
        match val {
            BitDeviceAuthKeyError::AuthenticatorFailure => Self::AuthenticatorFailure,
            BitDeviceAuthKeyError::Conversion => Self::Conversion,
            BitDeviceAuthKeyError::CredentialExcluded => Self::CredentialExcluded,
            BitDeviceAuthKeyError::InvalidRecordIdentifier => Self::InvalidRecordIdentifier,
            BitDeviceAuthKeyError::InvalidWebVaultUrl => Self::InvalidWebVaultUrl,
            BitDeviceAuthKeyError::MissingDeviceAuthKey => Self::MissingDeviceAuthKey,
            BitDeviceAuthKeyError::UnregisterFailure => Self::UnregisterFailure,
            BitDeviceAuthKeyError::InvalidCoseKey => Self::InvalidCoseKey,
            BitDeviceAuthKeyError::InvalidPublicKeyCredentialDescriptor => {
                Self::InvalidPublicKeyCredentialDescriptor
            }
            BitDeviceAuthKeyError::MasterPasswordHash => Self::MasterPasswordHash,
            BitDeviceAuthKeyError::MissingCredentialId => Self::MissingCredentialId,
            BitDeviceAuthKeyError::MissingHmacSecret => Self::MissingHmacSecret,
            BitDeviceAuthKeyError::MissingUserHandle => Self::MissingUserHandle,
            BitDeviceAuthKeyError::NotImplemented => Self::NotImplemented,
            BitDeviceAuthKeyError::RetrieveRegistrationOptionsFailure => {
                Self::RetrieveRegistrationOptionsFailure
            }
            BitDeviceAuthKeyError::PrfFailure => Self::PrfFailure,
            BitDeviceAuthKeyError::SubmitRegistrationFailure => Self::SubmitRegistrationFailure,
            BitDeviceAuthKeyError::UserCancelled => Self::UserCancelled,
            BitDeviceAuthKeyError::Unknown { reason } => Self::Unknown { reason },
        }
    }
}
