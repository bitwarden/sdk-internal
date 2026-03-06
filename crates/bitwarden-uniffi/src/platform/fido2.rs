use std::sync::Arc;

use bitwarden_core::platform::SecretVerificationRequest;
use bitwarden_crypto::Kdf;
use bitwarden_fido::{
    CheckUserOptions, ClientData, DeviceAuthKeyError, DeviceAuthKeyGetAssertionResult,
    DeviceAuthKeyMetadata, DeviceAuthKeyRecord, Fido2CallbackError as BitFido2CallbackError,
    Fido2CredentialAutofillView, GetAssertionRequest, GetAssertionResult, MakeCredentialRequest,
    MakeCredentialResult, Origin, PublicKeyCredentialAuthenticatorAssertionResponse,
    PublicKeyCredentialAuthenticatorAttestationResponse, PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
};
use bitwarden_vault::{CipherListView, CipherView, EncryptionContext, Fido2CredentialNewView};

use crate::error::{Error, Result};

#[derive(uniffi::Object)]
pub struct ClientFido2(pub(crate) bitwarden_fido::ClientFido2);

#[uniffi::export]
impl ClientFido2 {
    pub fn authenticator(
        &self,
        user_interface: Arc<dyn Fido2UserInterface>,
        credential_store: Arc<dyn Fido2CredentialStore>,
    ) -> Arc<ClientFido2Authenticator> {
        Arc::new(ClientFido2Authenticator(
            self.0.clone(),
            user_interface,
            credential_store,
        ))
    }

    pub fn device_auth_key_authenticator(
        &self,
        credential_store: Arc<dyn DeviceAuthKeyStore>,
    ) -> Arc<ClientDeviceAuthKeyAuthenticator> {
        Arc::new(ClientDeviceAuthKeyAuthenticator {
            client: self.0.clone(),
            store: credential_store,
        })
    }

    pub fn client(
        &self,
        user_interface: Arc<dyn Fido2UserInterface>,
        credential_store: Arc<dyn Fido2CredentialStore>,
    ) -> Arc<ClientFido2Client> {
        Arc::new(ClientFido2Client(ClientFido2Authenticator(
            self.0.clone(),
            user_interface,
            credential_store,
        )))
    }

    pub fn decrypt_fido2_autofill_credentials(
        &self,
        cipher_view: CipherView,
    ) -> Result<Vec<Fido2CredentialAutofillView>> {
        let result = self
            .0
            .decrypt_fido2_autofill_credentials(cipher_view)
            .map_err(Error::DecryptFido2AutofillCredentials)?;

        Ok(result)
    }
}

#[derive(uniffi::Object)]
pub struct ClientFido2Authenticator(
    pub(crate) bitwarden_fido::ClientFido2,
    pub(crate) Arc<dyn Fido2UserInterface>,
    pub(crate) Arc<dyn Fido2CredentialStore>,
);

#[uniffi::export]
impl ClientFido2Authenticator {
    pub async fn make_credential(
        &self,
        request: MakeCredentialRequest,
    ) -> Result<MakeCredentialResult> {
        let ui = UniffiTraitBridge(self.1.as_ref());
        let cs = UniffiTraitBridge(self.2.as_ref());
        let mut auth = self.0.create_authenticator(&ui, &cs);

        let result = auth
            .make_credential(request)
            .await
            .map_err(Error::MakeCredential)?;
        Ok(result)
    }

    pub async fn get_assertion(&self, request: GetAssertionRequest) -> Result<GetAssertionResult> {
        let ui = UniffiTraitBridge(self.1.as_ref());
        let cs = UniffiTraitBridge(self.2.as_ref());
        let mut auth = self.0.create_authenticator(&ui, &cs);

        let result = auth
            .get_assertion(request)
            .await
            .map_err(Error::GetAssertion)?;
        Ok(result)
    }

    pub async fn silently_discover_credentials(
        &self,
        rp_id: String,
        user_handle: Option<Vec<u8>>,
    ) -> Result<Vec<Fido2CredentialAutofillView>> {
        let ui = UniffiTraitBridge(self.1.as_ref());
        let cs = UniffiTraitBridge(self.2.as_ref());
        let mut auth = self.0.create_authenticator(&ui, &cs);

        let result = auth
            .silently_discover_credentials(rp_id, user_handle)
            .await
            .map_err(Error::SilentlyDiscoverCredentials)?;
        Ok(result)
    }

    pub async fn credentials_for_autofill(&self) -> Result<Vec<Fido2CredentialAutofillView>> {
        let ui = UniffiTraitBridge(self.1.as_ref());
        let cs = UniffiTraitBridge(self.2.as_ref());
        let mut auth = self.0.create_authenticator(&ui, &cs);

        let result = auth
            .credentials_for_autofill()
            .await
            .map_err(Error::CredentialsForAutofill)?;
        Ok(result)
    }
}

#[derive(uniffi::Object)]
pub struct ClientFido2Client(pub(crate) ClientFido2Authenticator);

#[uniffi::export]
impl ClientFido2Client {
    pub async fn register(
        &self,
        origin: Origin,
        request: String,
        client_data: ClientData,
    ) -> Result<PublicKeyCredentialAuthenticatorAttestationResponse> {
        let ui = UniffiTraitBridge(self.0.1.as_ref());
        let cs = UniffiTraitBridge(self.0.2.as_ref());
        let mut client = self.0.0.create_client(&ui, &cs);

        let result = client
            .register(origin, request, client_data)
            .await
            .map_err(Error::Fido2Client)?;
        Ok(result)
    }

    pub async fn authenticate(
        &self,
        origin: Origin,
        request: String,
        client_data: ClientData,
    ) -> Result<PublicKeyCredentialAuthenticatorAssertionResponse> {
        let ui = UniffiTraitBridge(self.0.1.as_ref());
        let cs = UniffiTraitBridge(self.0.2.as_ref());
        let mut client = self.0.0.create_client(&ui, &cs);

        let result = client
            .authenticate(origin, request, client_data)
            .await
            .map_err(Error::Fido2Client)?;
        Ok(result)
    }
}

// Note that uniffi doesn't support external traits for now it seems, so we have to duplicate them
// here.

#[allow(dead_code)]
#[derive(uniffi::Record)]
pub struct CheckUserResult {
    user_present: bool,
    user_verified: bool,
}

impl From<CheckUserResult> for bitwarden_fido::CheckUserResult {
    fn from(val: CheckUserResult) -> Self {
        Self {
            user_present: val.user_present,
            user_verified: val.user_verified,
        }
    }
}

#[allow(dead_code)]
#[derive(uniffi::Record)]
pub struct CheckUserAndPickCredentialForCreationResult {
    cipher: CipherViewWrapper,
    check_user_result: CheckUserResult,
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum Fido2CallbackError {
    #[error("The operation requires user interaction")]
    UserInterfaceRequired,

    #[error("The operation was cancelled by the user")]
    OperationCancelled,

    #[error("Unknown error: {reason}")]
    Unknown { reason: String },
}

// Need to implement this From<> impl in order to handle unexpected callback errors.  See the
// following page in the Uniffi user guide:
// <https://mozilla.github.io/uniffi-rs/foreign_traits.html#error-handling>
impl From<uniffi::UnexpectedUniFFICallbackError> for Fido2CallbackError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::Unknown { reason: e.reason }
    }
}

impl From<Fido2CallbackError> for BitFido2CallbackError {
    fn from(val: Fido2CallbackError) -> Self {
        match val {
            Fido2CallbackError::UserInterfaceRequired => Self::UserInterfaceRequired,
            Fido2CallbackError::OperationCancelled => Self::OperationCancelled,
            Fido2CallbackError::Unknown { reason } => Self::Unknown(reason),
        }
    }
}

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait Fido2UserInterface: Send + Sync {
    async fn check_user(
        &self,
        options: CheckUserOptions,
        hint: UIHint,
    ) -> Result<CheckUserResult, Fido2CallbackError>;
    async fn pick_credential_for_authentication(
        &self,
        available_credentials: Vec<CipherView>,
    ) -> Result<CipherViewWrapper, Fido2CallbackError>;
    async fn check_user_and_pick_credential_for_creation(
        &self,
        options: CheckUserOptions,
        new_credential: Fido2CredentialNewView,
    ) -> Result<CheckUserAndPickCredentialForCreationResult, Fido2CallbackError>;
    fn is_verification_enabled(&self) -> bool;
}

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait Fido2CredentialStore: Send + Sync {
    async fn find_credentials(
        &self,
        ids: Option<Vec<Vec<u8>>>,
        rip_id: String,
        user_handle: Option<Vec<u8>>,
    ) -> Result<Vec<CipherView>, Fido2CallbackError>;

    async fn all_credentials(&self) -> Result<Vec<CipherListView>, Fido2CallbackError>;

    async fn save_credential(&self, cred: EncryptionContext) -> Result<(), Fido2CallbackError>;
}

#[derive(uniffi::Object)]
pub struct ClientDeviceAuthKeyAuthenticator {
    client: bitwarden_fido::ClientFido2,
    store: Arc<dyn DeviceAuthKeyStore>,
}

#[uniffi::export]
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
            .map_err(Error::DeviceAuthKeyError)
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
            .map_err(Error::DeviceAuthKeyError)
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
            .map_err(Error::DeviceAuthKeyError)
    }
}

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait DeviceAuthKeyStore: Send + Sync {
    async fn create_record(&self, record: DeviceAuthKeyRecord) -> Result<(), DeviceAuthKeyError>;
    async fn create_metadata(
        &self,
        metadata: DeviceAuthKeyMetadata,
    ) -> Result<(), DeviceAuthKeyError>;
    async fn get_metadata(&self) -> Result<Option<DeviceAuthKeyMetadata>, DeviceAuthKeyError>;
    async fn get_record(&self) -> Result<Option<DeviceAuthKeyRecord>, DeviceAuthKeyError>;
    async fn delete_record_and_metadata(&self) -> Result<(), DeviceAuthKeyError>;
}

// See note on UniffiTraitBridge below
#[async_trait::async_trait]
impl bitwarden_fido::DeviceAuthKeyStore for UniffiTraitBridge<&dyn DeviceAuthKeyStore> {
    async fn create_record(
        &mut self,
        record: DeviceAuthKeyRecord,
    ) -> Result<(), DeviceAuthKeyError> {
        self.0.create_record(record).await
    }

    async fn create_metadata(
        &mut self,
        metadata: DeviceAuthKeyMetadata,
    ) -> Result<(), DeviceAuthKeyError> {
        self.0.create_metadata(metadata).await
    }

    async fn get_metadata(&self) -> Result<Option<DeviceAuthKeyMetadata>, DeviceAuthKeyError> {
        self.0.get_metadata().await
    }

    async fn get_record(&self) -> Result<Option<DeviceAuthKeyRecord>, DeviceAuthKeyError> {
        self.0.get_record().await
    }

    async fn delete_record_and_metadata(&mut self) -> Result<(), DeviceAuthKeyError> {
        self.0.delete_record_and_metadata().await
    }
}

// Because uniffi doesn't support external traits, we have to make a copy of the trait here.
// Ideally we'd want to implement the original trait for every item that implements our local copy,
// but the orphan rules don't allow us to blanket implement an external trait. So we have to wrap
// the trait in a newtype and implement the trait for the newtype.
struct UniffiTraitBridge<T>(T);

#[async_trait::async_trait]
impl bitwarden_fido::Fido2CredentialStore for UniffiTraitBridge<&dyn Fido2CredentialStore> {
    async fn find_credentials(
        &self,
        ids: Option<Vec<Vec<u8>>>,
        rip_id: String,
        user_handle: Option<Vec<u8>>,
    ) -> Result<Vec<CipherView>, BitFido2CallbackError> {
        self.0
            .find_credentials(ids, rip_id, user_handle)
            .await
            .map_err(Into::into)
    }

    async fn all_credentials(&self) -> Result<Vec<CipherListView>, BitFido2CallbackError> {
        self.0.all_credentials().await.map_err(Into::into)
    }

    async fn save_credential(&self, cred: EncryptionContext) -> Result<(), BitFido2CallbackError> {
        self.0.save_credential(cred).await.map_err(Into::into)
    }
}

// Uniffi seems to have trouble generating code for Android when a local trait returns a type from
// an external crate. If the type is small we can just copy it over and convert back and forth, but
// Cipher is too big for that to be practical. So we wrap it in a newtype, which is local to the
// trait and so we can sidestep the Uniffi issue
#[derive(uniffi::Record)]
pub struct CipherViewWrapper {
    cipher: CipherView,
}

#[derive(uniffi::Enum)]
pub enum UIHint {
    InformExcludedCredentialFound(CipherView),
    InformNoCredentialsFound,
    RequestNewCredential(PublicKeyCredentialUserEntity, PublicKeyCredentialRpEntity),
    RequestExistingCredential(CipherView),
}

impl From<bitwarden_fido::UiHint<'_, CipherView>> for UIHint {
    fn from(hint: bitwarden_fido::UiHint<'_, CipherView>) -> Self {
        use bitwarden_fido::UiHint as BWUIHint;
        match hint {
            BWUIHint::InformExcludedCredentialFound(cipher) => {
                UIHint::InformExcludedCredentialFound(cipher.clone())
            }
            BWUIHint::InformNoCredentialsFound => UIHint::InformNoCredentialsFound,
            BWUIHint::RequestNewCredential(user, rp) => UIHint::RequestNewCredential(
                PublicKeyCredentialUserEntity {
                    id: user.id.clone().into(),
                    name: user.name.clone().unwrap_or_default(),
                    display_name: user.display_name.clone().unwrap_or_default(),
                },
                PublicKeyCredentialRpEntity {
                    id: rp.id.clone(),
                    name: rp.name.clone(),
                },
            ),
            BWUIHint::RequestExistingCredential(cipher) => {
                UIHint::RequestExistingCredential(cipher.clone())
            }
        }
    }
}

#[async_trait::async_trait]
impl bitwarden_fido::Fido2UserInterface for UniffiTraitBridge<&dyn Fido2UserInterface> {
    async fn check_user<'a>(
        &self,
        options: CheckUserOptions,
        hint: bitwarden_fido::UiHint<'a, CipherView>,
    ) -> Result<bitwarden_fido::CheckUserResult, BitFido2CallbackError> {
        self.0
            .check_user(options.clone(), hint.into())
            .await
            .map(Into::into)
            .map_err(Into::into)
    }
    async fn pick_credential_for_authentication(
        &self,
        available_credentials: Vec<CipherView>,
    ) -> Result<CipherView, BitFido2CallbackError> {
        self.0
            .pick_credential_for_authentication(available_credentials)
            .await
            .map(|v| v.cipher)
            .map_err(Into::into)
    }
    async fn check_user_and_pick_credential_for_creation(
        &self,
        options: CheckUserOptions,
        new_credential: Fido2CredentialNewView,
    ) -> Result<(CipherView, bitwarden_fido::CheckUserResult), BitFido2CallbackError> {
        self.0
            .check_user_and_pick_credential_for_creation(options, new_credential)
            .await
            .map(|v| (v.cipher.cipher, v.check_user_result.into()))
            .map_err(Into::into)
    }
    fn is_verification_enabled(&self) -> bool {
        self.0.is_verification_enabled()
    }
}
