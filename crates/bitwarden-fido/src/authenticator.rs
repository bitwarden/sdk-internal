use std::sync::Mutex;

use bitwarden_core::Client;
use bitwarden_crypto::CryptoError;
use bitwarden_vault::{CipherError, CipherView, EncryptionContext};
use itertools::Itertools;
use passkey::{
    authenticator::{Authenticator, DiscoverabilitySupport, StoreInfo, UiHint, UserCheck},
    types::{
        Passkey,
        ctap2::{self, Ctap2Error, StatusCode, VendorError},
    },
};
use thiserror::Error;
use tracing::error;

use super::{
    AAGUID, CheckUserOptions, CipherViewContainer, Fido2CredentialStore, Fido2UserInterface,
    SelectedCredential, UnknownEnumError, try_from_credential_new_view, types::*,
};
use crate::{
    Fido2CallbackError, FillCredentialError, InvalidGuidError, fill_with_credential,
    string_to_guid_bytes, try_from_credential_full,
};

#[derive(Debug, Error)]
pub enum GetSelectedCredentialError {
    #[error("No selected credential available")]
    NoSelectedCredential,
    #[error("No fido2 credentials found")]
    NoCredentialFound,

    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum MakeCredentialError {
    #[error(transparent)]
    PublicKeyCredentialParameters(#[from] PublicKeyCredentialParametersError),
    #[error(transparent)]
    UnknownEnum(#[from] UnknownEnumError),
    #[error("Missing attested_credential_data")]
    MissingAttestedCredentialData,
    #[error("make_credential error: {0}")]
    Other(String),
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum GetAssertionError {
    #[error(transparent)]
    UnknownEnum(#[from] UnknownEnumError),
    #[error(transparent)]
    GetSelectedCredential(#[from] GetSelectedCredentialError),
    #[error(transparent)]
    InvalidGuid(#[from] InvalidGuidError),
    #[error("missing user")]
    MissingUser,
    #[error("get_assertion error: {0}")]
    Other(String),
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum SilentlyDiscoverCredentialsError {
    #[error(transparent)]
    Cipher(#[from] CipherError),
    #[error(transparent)]
    InvalidGuid(#[from] InvalidGuidError),
    #[error(transparent)]
    Fido2Callback(#[from] Fido2CallbackError),
    #[error(transparent)]
    FromCipherView(#[from] Fido2CredentialAutofillViewError),
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum CredentialsForAutofillError {
    #[error(transparent)]
    Cipher(#[from] CipherError),
    #[error(transparent)]
    InvalidGuid(#[from] InvalidGuidError),
    #[error(transparent)]
    Fido2Callback(#[from] Fido2CallbackError),
    #[error(transparent)]
    FromCipherView(#[from] Fido2CredentialAutofillViewError),
}

#[allow(missing_docs)]
pub struct Fido2Authenticator<'a> {
    pub client: &'a Client,
    pub user_interface: &'a dyn Fido2UserInterface,
    pub credential_store: &'a dyn Fido2CredentialStore,

    pub(crate) selected_cipher: Mutex<Option<CipherView>>,
    pub(crate) requested_uv: Mutex<Option<UV>>,
}

impl<'a> Fido2Authenticator<'a> {
    #[allow(missing_docs)]
    pub fn new(
        client: &'a Client,
        user_interface: &'a dyn Fido2UserInterface,
        credential_store: &'a dyn Fido2CredentialStore,
    ) -> Fido2Authenticator<'a> {
        Fido2Authenticator {
            client,
            user_interface,
            credential_store,
            selected_cipher: Mutex::new(None),
            requested_uv: Mutex::new(None),
        }
    }

    #[allow(missing_docs)]
    pub async fn make_credential(
        &mut self,
        request: MakeCredentialRequest,
    ) -> Result<MakeCredentialResult, MakeCredentialError> {
        // Insert the received UV to be able to return it later in check_user
        self.requested_uv
            .get_mut()
            .expect("Mutex is not poisoned")
            .replace(request.options.uv);

        let mut authenticator = self.get_authenticator(true);

        let response = authenticator
            .make_credential(ctap2::make_credential::Request {
                client_data_hash: request.client_data_hash.into(),
                rp: passkey::types::ctap2::make_credential::PublicKeyCredentialRpEntity {
                    id: request.rp.id,
                    name: request.rp.name,
                },
                user: passkey::types::webauthn::PublicKeyCredentialUserEntity {
                    id: request.user.id.into(),
                    display_name: request.user.display_name,
                    name: request.user.name,
                },
                pub_key_cred_params: request
                    .pub_key_cred_params
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<_, _>>()?,
                exclude_list: request
                    .exclude_list
                    .map(|x| x.into_iter().map(TryInto::try_into).collect())
                    .transpose()?,
                // TODO(PM-30510): Even though we forward the extensions to the
                // authenticator, they will not be processed until they are
                // enabled in the authenticator configuration.
                extensions: request
                    .extensions
                    .map(passkey::types::ctap2::make_credential::ExtensionInputs::from),
                options: passkey::types::ctap2::make_credential::Options {
                    rk: request.options.rk,
                    up: true,
                    uv: self.convert_requested_uv(request.options.uv),
                },
                pin_auth: None,
                pin_protocol: None,
            })
            .await;

        let response = match response {
            Ok(x) => x,
            Err(e) => return Err(MakeCredentialError::Other(format!("{e:?}"))),
        };

        let attestation_object = response.as_webauthn_bytes().to_vec();
        let authenticator_data = response.auth_data.to_vec();
        let attested_credential_data = response
            .auth_data
            .attested_credential_data
            .ok_or(MakeCredentialError::MissingAttestedCredentialData)?;
        let credential_id = attested_credential_data.credential_id().to_vec();
        let extensions = response.unsigned_extension_outputs.into();

        Ok(MakeCredentialResult {
            authenticator_data,
            attestation_object,
            credential_id,
            extensions,
        })
    }

    #[allow(missing_docs)]
    pub async fn get_assertion(
        &mut self,
        request: GetAssertionRequest,
    ) -> Result<GetAssertionResult, GetAssertionError> {
        // Insert the received UV to be able to return it later in check_user
        self.requested_uv
            .get_mut()
            .expect("Mutex is not poisoned")
            .replace(request.options.uv);

        let mut authenticator = self.get_authenticator(false);

        let response = authenticator
            .get_assertion(ctap2::get_assertion::Request {
                rp_id: request.rp_id,
                client_data_hash: request.client_data_hash.into(),
                allow_list: request
                    .allow_list
                    .map(|l| {
                        l.into_iter()
                            .map(TryInto::try_into)
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()?,
                // TODO(PM-30510): Even though we forward the extensions to the
                // authenticator, they will not be processed until they are
                // enabled in the authenticator configuration.
                extensions: request
                    .extensions
                    .map(passkey::types::ctap2::get_assertion::ExtensionInputs::from),
                options: passkey::types::ctap2::make_credential::Options {
                    rk: request.options.rk,
                    up: true,
                    uv: self.convert_requested_uv(request.options.uv),
                },
                pin_auth: None,
                pin_protocol: None,
            })
            .await;

        let response = match response {
            Ok(x) => x,
            Err(e) => return Err(GetAssertionError::Other(format!("{e:?}"))),
        };

        let selected_credential = self.get_selected_credential()?;
        let authenticator_data = response.auth_data.to_vec();
        let credential_id = string_to_guid_bytes(&selected_credential.credential.credential_id)?;
        let extensions = response.unsigned_extension_outputs.into();

        Ok(GetAssertionResult {
            credential_id,
            authenticator_data,
            signature: response.signature.into(),
            user_handle: response
                .user
                .ok_or(GetAssertionError::MissingUser)?
                .id
                .into(),
            selected_credential,
            extensions,
        })
    }

    #[allow(missing_docs)]
    pub async fn silently_discover_credentials(
        &mut self,
        rp_id: String,
        user_handle: Option<Vec<u8>>,
    ) -> Result<Vec<Fido2CredentialAutofillView>, SilentlyDiscoverCredentialsError> {
        let key_store = self.client.internal.get_key_store();
        let result = self
            .credential_store
            .find_credentials(None, rp_id, user_handle)
            .await?;

        let mut ctx = key_store.context();
        result
            .into_iter()
            .map(
                |cipher| -> Result<Vec<Fido2CredentialAutofillView>, SilentlyDiscoverCredentialsError> {
                    Ok(Fido2CredentialAutofillView::from_cipher_view(&cipher, &mut ctx)?)
                },
            )
            .flatten_ok()
            .collect()
    }

    /// Returns all Fido2 credentials that can be used for autofill, in a view
    /// tailored for integration with OS autofill systems.
    pub async fn credentials_for_autofill(
        &mut self,
    ) -> Result<Vec<Fido2CredentialAutofillView>, CredentialsForAutofillError> {
        let all_credentials = self.credential_store.all_credentials().await?;

        all_credentials
            .into_iter()
            .map(
                |cipher| -> Result<Vec<Fido2CredentialAutofillView>, CredentialsForAutofillError> {
                    Ok(Fido2CredentialAutofillView::from_cipher_list_view(&cipher)?)
                },
            )
            .flatten_ok()
            .collect()
    }

    pub(super) fn get_authenticator(
        &self,
        create_credential: bool,
    ) -> Authenticator<CredentialStoreImpl<'_>, UserValidationMethodImpl<'_>> {
        Authenticator::new(
            AAGUID,
            CredentialStoreImpl {
                authenticator: self,
                create_credential,
            },
            UserValidationMethodImpl {
                authenticator: self,
            },
        )
    }

    fn convert_requested_uv(&self, uv: UV) -> bool {
        let verification_enabled = self.user_interface.is_verification_enabled();
        match (uv, verification_enabled) {
            (UV::Preferred, true) => true,
            (UV::Preferred, false) => false,
            (UV::Required, _) => true,
            (UV::Discouraged, _) => false,
        }
    }

    pub(super) fn get_selected_credential(
        &self,
    ) -> Result<SelectedCredential, GetSelectedCredentialError> {
        let key_store = self.client.internal.get_key_store();

        let cipher = self
            .selected_cipher
            .lock()
            .expect("Mutex is not poisoned")
            .clone()
            .ok_or(GetSelectedCredentialError::NoSelectedCredential)?;

        let creds = cipher.decrypt_fido2_credentials(&mut key_store.context())?;

        let credential = creds
            .first()
            .ok_or(GetSelectedCredentialError::NoCredentialFound)?
            .clone();

        Ok(SelectedCredential { cipher, credential })
    }
}

pub(super) struct CredentialStoreImpl<'a> {
    authenticator: &'a Fido2Authenticator<'a>,
    create_credential: bool,
}
pub(super) struct UserValidationMethodImpl<'a> {
    authenticator: &'a Fido2Authenticator<'a>,
}

#[async_trait::async_trait]
impl passkey::authenticator::CredentialStore for CredentialStoreImpl<'_> {
    type PasskeyItem = CipherViewContainer;
    async fn find_credentials(
        &self,
        ids: Option<&[passkey::types::webauthn::PublicKeyCredentialDescriptor]>,
        rp_id: &str,
        user_handle: Option<&[u8]>,
    ) -> Result<Vec<Self::PasskeyItem>, StatusCode> {
        #[derive(Debug, Error)]
        enum InnerError {
            #[error(transparent)]
            Cipher(#[from] CipherError),
            #[error(transparent)]
            Crypto(#[from] CryptoError),
            #[error(transparent)]
            Fido2Callback(#[from] Fido2CallbackError),
        }

        // This is just a wrapper around the actual implementation to allow for ? error handling
        async fn inner(
            this: &CredentialStoreImpl<'_>,
            ids: Option<&[passkey::types::webauthn::PublicKeyCredentialDescriptor]>,
            rp_id: &str,
            user_handle: Option<&[u8]>,
        ) -> Result<Vec<CipherViewContainer>, InnerError> {
            let ids: Option<Vec<Vec<u8>>> =
                ids.map(|ids| ids.iter().map(|id| id.id.clone().into()).collect());

            let ciphers = this
                .authenticator
                .credential_store
                .find_credentials(ids, rp_id.to_string(), user_handle.map(|h| h.to_vec()))
                .await?;

            // Remove any that don't have Fido2 credentials
            let creds: Vec<_> = ciphers
                .into_iter()
                .filter(|c| {
                    c.login
                        .as_ref()
                        .and_then(|l| l.fido2_credentials.as_ref())
                        .is_some()
                })
                .collect();

            let key_store = this.authenticator.client.internal.get_key_store();

            // When using the credential for authentication we have to ask the user to pick one.
            if this.create_credential {
                Ok(creds
                    .into_iter()
                    .map(|c| CipherViewContainer::new(c, &mut key_store.context()))
                    .collect::<Result<_, _>>()?)
            } else {
                let picked = this
                    .authenticator
                    .user_interface
                    .pick_credential_for_authentication(creds)
                    .await?;

                // Store the selected credential for later use
                this.authenticator
                    .selected_cipher
                    .lock()
                    .expect("Mutex is not poisoned")
                    .replace(picked.clone());

                Ok(vec![CipherViewContainer::new(
                    picked,
                    &mut key_store.context(),
                )?])
            }
        }

        inner(self, ids, rp_id, user_handle).await.map_err(|error| {
            error!(%error, "Error finding credentials.");
            VendorError::try_from(0xF0)
                .expect("Valid vendor error code")
                .into()
        })
    }

    async fn save_credential(
        &mut self,
        cred: Passkey,
        user: passkey::types::ctap2::make_credential::PublicKeyCredentialUserEntity,
        rp: passkey::types::ctap2::make_credential::PublicKeyCredentialRpEntity,
        options: passkey::types::ctap2::get_assertion::Options,
    ) -> Result<(), StatusCode> {
        #[derive(Debug, Error)]
        enum InnerError {
            #[error("Client User Id has not been set")]
            MissingUserId,
            #[error(transparent)]
            FillCredential(#[from] FillCredentialError),
            #[error(transparent)]
            Cipher(#[from] CipherError),
            #[error(transparent)]
            Crypto(#[from] CryptoError),
            #[error(transparent)]
            Fido2Callback(#[from] Fido2CallbackError),

            #[error("No selected credential available")]
            NoSelectedCredential,
        }

        // This is just a wrapper around the actual implementation to allow for ? error handling
        async fn inner(
            this: &mut CredentialStoreImpl<'_>,
            cred: Passkey,
            user: passkey::types::ctap2::make_credential::PublicKeyCredentialUserEntity,
            rp: passkey::types::ctap2::make_credential::PublicKeyCredentialRpEntity,
            options: passkey::types::ctap2::get_assertion::Options,
        ) -> Result<(), InnerError> {
            let user_id = this
                .authenticator
                .client
                .internal
                .get_user_id()
                .ok_or(InnerError::MissingUserId)?;
            let cred = try_from_credential_full(cred, user, rp, options)?;

            // Get the previously selected cipher and add the new credential to it
            let mut selected: CipherView = this
                .authenticator
                .selected_cipher
                .lock()
                .expect("Mutex is not poisoned")
                .clone()
                .ok_or(InnerError::NoSelectedCredential)?;

            let key_store = this.authenticator.client.internal.get_key_store();

            selected.set_new_fido2_credentials(&mut key_store.context(), vec![cred])?;

            // Store the updated credential for later use
            this.authenticator
                .selected_cipher
                .lock()
                .expect("Mutex is not poisoned")
                .replace(selected.clone());

            // Encrypt the updated cipher before sending it to the clients to be stored
            let encrypted = key_store.encrypt(selected)?;

            this.authenticator
                .credential_store
                .save_credential(EncryptionContext {
                    cipher: encrypted,
                    encrypted_for: user_id,
                })
                .await?;

            Ok(())
        }

        inner(self, cred, user, rp, options).await.map_err(|error| {
            error!(%error, "Error saving credential.");
            VendorError::try_from(0xF1)
                .expect("Valid vendor error code")
                .into()
        })
    }

    async fn update_credential(&mut self, cred: Passkey) -> Result<(), StatusCode> {
        #[derive(Debug, Error)]
        enum InnerError {
            #[error("Client User Id has not been set")]
            MissingUserId,
            #[error(transparent)]
            InvalidGuid(#[from] InvalidGuidError),
            #[error("Credential ID does not match selected credential")]
            CredentialIdMismatch,
            #[error(transparent)]
            FillCredential(#[from] FillCredentialError),
            #[error(transparent)]
            Cipher(#[from] CipherError),
            #[error(transparent)]
            Crypto(#[from] CryptoError),
            #[error(transparent)]
            Fido2Callback(#[from] Fido2CallbackError),
            #[error(transparent)]
            GetSelectedCredential(#[from] GetSelectedCredentialError),
        }

        // This is just a wrapper around the actual implementation to allow for ? error handling
        async fn inner(
            this: &mut CredentialStoreImpl<'_>,
            cred: Passkey,
        ) -> Result<(), InnerError> {
            let user_id = this
                .authenticator
                .client
                .internal
                .get_user_id()
                .ok_or(InnerError::MissingUserId)?;
            // Get the previously selected cipher and update the credential
            let selected = this.authenticator.get_selected_credential()?;

            // Check that the provided credential ID matches the selected credential
            let new_id: &Vec<u8> = &cred.credential_id;
            let selected_id = string_to_guid_bytes(&selected.credential.credential_id)?;
            if new_id != &selected_id {
                return Err(InnerError::CredentialIdMismatch);
            }

            let cred = fill_with_credential(&selected.credential, cred)?;

            let key_store = this.authenticator.client.internal.get_key_store();

            let mut selected = selected.cipher;
            selected.set_new_fido2_credentials(&mut key_store.context(), vec![cred])?;

            // Store the updated credential for later use
            this.authenticator
                .selected_cipher
                .lock()
                .expect("Mutex is not poisoned")
                .replace(selected.clone());

            // Encrypt the updated cipher before sending it to the clients to be stored
            let encrypted = key_store.encrypt(selected)?;

            this.authenticator
                .credential_store
                .save_credential(EncryptionContext {
                    cipher: encrypted,
                    encrypted_for: user_id,
                })
                .await?;

            Ok(())
        }

        inner(self, cred).await.map_err(|error| {
            error!(%error, "Error updating credential.");
            VendorError::try_from(0xF2)
                .expect("Valid vendor error code")
                .into()
        })
    }

    async fn get_info(&self) -> StoreInfo {
        StoreInfo {
            discoverability: DiscoverabilitySupport::Full,
        }
    }
}

#[async_trait::async_trait]
impl passkey::authenticator::UserValidationMethod for UserValidationMethodImpl<'_> {
    type PasskeyItem = CipherViewContainer;

    async fn check_user<'a>(
        &self,
        hint: UiHint<'a, Self::PasskeyItem>,
        presence: bool,
        _verification: bool,
    ) -> Result<UserCheck, Ctap2Error> {
        let verification = self
            .authenticator
            .requested_uv
            .lock()
            .expect("Mutex is not poisoned")
            .ok_or(Ctap2Error::UserVerificationInvalid)?;

        let options = CheckUserOptions {
            require_presence: presence,
            require_verification: verification.into(),
        };

        let result = match hint {
            UiHint::RequestNewCredential(user, rp) => {
                let new_credential = try_from_credential_new_view(user, rp)
                    .map_err(|_| Ctap2Error::InvalidCredential)?;

                let (cipher_view, user_check) = self
                    .authenticator
                    .user_interface
                    .check_user_and_pick_credential_for_creation(options, new_credential)
                    .await
                    .map_err(|_| Ctap2Error::OperationDenied)?;

                self.authenticator
                    .selected_cipher
                    .lock()
                    .expect("Mutex is not poisoned")
                    .replace(cipher_view);

                Ok(user_check)
            }
            _ => {
                self.authenticator
                    .user_interface
                    .check_user(options, map_ui_hint(hint))
                    .await
            }
        };

        let result = result.map_err(|error| {
            error!(%error, "Error checking user.");
            Ctap2Error::UserVerificationInvalid
        })?;

        Ok(UserCheck {
            presence: result.user_present,
            verification: result.user_verified,
        })
    }

    fn is_presence_enabled(&self) -> bool {
        true
    }

    fn is_verification_enabled(&self) -> Option<bool> {
        Some(self.authenticator.user_interface.is_verification_enabled())
    }
}

fn map_ui_hint(hint: UiHint<'_, CipherViewContainer>) -> UiHint<'_, CipherView> {
    use UiHint::*;
    match hint {
        InformExcludedCredentialFound(c) => InformExcludedCredentialFound(&c.cipher),
        InformNoCredentialsFound => InformNoCredentialsFound,
        RequestNewCredential(u, r) => RequestNewCredential(u, r),
        RequestExistingCredential(c) => RequestExistingCredential(&c.cipher),
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use bitwarden_core::{
        Client,
        key_management::{KeyIds, SymmetricKeyId},
    };
    use bitwarden_crypto::{KeyStoreContext, PrimitiveEncryptable, SymmetricCryptoKey};
    use bitwarden_encoding::B64Url;
    use bitwarden_vault::{
        CipherListView, CipherRepromptType, CipherType, CipherView, EncryptionContext,
        Fido2Credential, Fido2CredentialNewView, LoginView,
    };
    use passkey::authenticator::UiHint;

    use super::Fido2Authenticator;
    use crate::{
        CheckUserOptions, CheckUserResult, Fido2CallbackError, Fido2CredentialStore,
        Fido2UserInterface, GetAssertionExtensionsInput, GetAssertionPrfInput, PrfInputValues,
        guid_bytes_to_string,
        types::{GetAssertionRequest, Options, UV},
    };

    struct MockUserInterface;

    #[async_trait]
    impl Fido2UserInterface for MockUserInterface {
        async fn check_user<'a>(
            &self,
            _options: CheckUserOptions,
            _hint: UiHint<'a, CipherView>,
        ) -> Result<CheckUserResult, Fido2CallbackError> {
            Ok(CheckUserResult {
                user_present: true,
                user_verified: true,
            })
        }

        async fn pick_credential_for_authentication(
            &self,
            available_credentials: Vec<CipherView>,
        ) -> Result<CipherView, Fido2CallbackError> {
            available_credentials
                .into_iter()
                .next()
                .ok_or(Fido2CallbackError::Unknown("no credentials".to_string()))
        }

        async fn check_user_and_pick_credential_for_creation(
            &self,
            _options: CheckUserOptions,
            _new_credential: Fido2CredentialNewView,
        ) -> Result<(CipherView, CheckUserResult), Fido2CallbackError> {
            unimplemented!("not needed for this test")
        }

        fn is_verification_enabled(&self) -> bool {
            true
        }
    }

    struct MockCredentialStore {
        cipher: CipherView,
    }

    #[async_trait]
    impl Fido2CredentialStore for MockCredentialStore {
        async fn find_credentials(
            &self,
            _ids: Option<Vec<Vec<u8>>>,
            _rp_id: String,
            _user_handle: Option<Vec<u8>>,
        ) -> Result<Vec<CipherView>, Fido2CallbackError> {
            Ok(vec![self.cipher.clone()])
        }

        async fn all_credentials(&self) -> Result<Vec<CipherListView>, Fido2CallbackError> {
            Ok(vec![])
        }

        async fn save_credential(
            &self,
            _cred: EncryptionContext,
        ) -> Result<(), Fido2CallbackError> {
            Ok(())
        }
    }

    static TEST_FIDO_CREDENTIAL_ID: &str = "a36f3d35-5dae-4d07-8b24-f89e11082090";
    static TEST_FIDO_RP_ID: &str = "example.com";
    static TEST_FIDO_USER_HANDLE: &str = "YWJjZA";
    // Hardcoded P-256 private key in PKCS8 DER format for testing
    static TEST_FIDO_P256_KEY: &[u8] = &[
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30,
        0x6b, 0x02, 0x01, 0x01, 0x04, 0x20, 0x06, 0x76, 0x5e, 0x85, 0xe0, 0x7f, 0xef, 0x43, 0xaa,
        0x17, 0xe0, 0x7a, 0xd7, 0x85, 0x63, 0x01, 0x80, 0x70, 0x8c, 0x6c, 0x61, 0x43, 0x7d, 0xc3,
        0xb1, 0xe6, 0xf9, 0x09, 0x24, 0xeb, 0x1f, 0xf5, 0xa1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x35,
        0x9a, 0x52, 0xf3, 0x82, 0x44, 0x66, 0x5f, 0x3f, 0xe2, 0xc4, 0x0b, 0x1c, 0x16, 0x34, 0xc5,
        0x60, 0x07, 0x3a, 0x25, 0xfe, 0x7e, 0x7f, 0x7f, 0xda, 0xd4, 0x1c, 0x36, 0x90, 0x00, 0xee,
        0xb1, 0x8e, 0x92, 0xb3, 0xac, 0x91, 0x7f, 0xb1, 0x8c, 0xa4, 0x85, 0xe7, 0x03, 0x07, 0xd1,
        0xf5, 0x5b, 0xd3, 0x7b, 0xc3, 0x56, 0x11, 0xdf, 0xbc, 0x7a, 0x97, 0x70, 0x32, 0x4b, 0x3c,
        0x84, 0x05, 0x71,
    ];

    fn create_test_cipher(ctx: &mut KeyStoreContext<KeyIds>) -> CipherView {
        let key = SymmetricKeyId::User;
        let key_value = B64Url::from(TEST_FIDO_P256_KEY).to_string();

        let fido2_credential = Fido2Credential {
            credential_id: TEST_FIDO_CREDENTIAL_ID.encrypt(ctx, key).unwrap(),
            key_type: "public-key".to_string().encrypt(ctx, key).unwrap(),
            key_algorithm: "ECDSA".to_string().encrypt(ctx, key).unwrap(),
            key_curve: "P-256".to_string().encrypt(ctx, key).unwrap(),
            key_value: key_value.encrypt(ctx, key).unwrap(),
            rp_id: TEST_FIDO_RP_ID.encrypt(ctx, key).unwrap(),
            user_handle: Some(TEST_FIDO_USER_HANDLE.encrypt(ctx, key).unwrap()),
            user_name: None,
            counter: "0".to_string().encrypt(ctx, key).unwrap(),
            rp_name: None,
            user_display_name: None,
            discoverable: "true".to_string().encrypt(ctx, key).unwrap(),
            creation_date: "2024-06-07T14:12:36.150Z".parse().unwrap(),
        };

        CipherView {
            id: Some("c2c7e624-dcfd-4f23-af41-b177014ffcb5".parse().unwrap()),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: "Test Login".to_string(),
            notes: None,
            r#type: CipherType::Login,
            login: Some(LoginView {
                username: None,
                password: None,
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: Some(vec![fido2_credential]),
            }),
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: None,
            bank_account: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: false,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            attachment_decryption_failures: None,
            fields: None,
            password_history: None,
            creation_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            archived_date: None,
        }
    }

    /// TODO(PM-30510): Even though we forward the extensions to the
    /// authenticator, we have disabled the configuration.
    /// When we implement PRF, this test should be updated to test that PRF _is_
    /// evaluated when PRF extension input is received.
    #[tokio::test]
    async fn test_prf_is_not_evaluated() {
        let client = Client::new(None);
        let user_key: SymmetricCryptoKey =
            "w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q=="
                .to_string()
                .try_into()
                .unwrap();

        #[allow(deprecated)]
        client
            .internal
            .get_key_store()
            .context_mut()
            .set_symmetric_key(SymmetricKeyId::User, user_key)
            .unwrap();

        let cipher = {
            let mut ctx = client.internal.get_key_store().context();
            create_test_cipher(&mut ctx)
        };

        let user_interface = MockUserInterface;
        let credential_store = MockCredentialStore { cipher };
        let mut authenticator =
            Fido2Authenticator::new(&client, &user_interface, &credential_store);

        let request = GetAssertionRequest {
            rp_id: "example.com".to_string(),
            client_data_hash: vec![0u8; 32],
            allow_list: None,
            options: Options {
                rk: false,
                uv: UV::Preferred,
            },
            extensions: Some(GetAssertionExtensionsInput {
                prf: Some(GetAssertionPrfInput {
                    eval: Some(PrfInputValues {
                        first: vec![1u8; 32],
                        second: None,
                    }),
                    eval_by_credential: None,
                }),
            }),
        };

        let result = authenticator.get_assertion(request).await.unwrap();
        assert_eq!(
            TEST_FIDO_CREDENTIAL_ID,
            guid_bytes_to_string(&result.credential_id).unwrap()
        );
        assert!(
            result.extensions.prf.is_none(),
            "PRF should not be evaluated"
        );
    }
}
