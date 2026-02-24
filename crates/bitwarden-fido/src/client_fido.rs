use bitwarden_core::Client;
use bitwarden_crypto::SymmetricCryptoKey;
use bitwarden_vault::CipherView;
use thiserror::Error;

use crate::{
    Fido2Authenticator, Fido2AuthenticatorOptions, Fido2Client, Fido2CredentialAutofillView,
    Fido2CredentialAutofillViewError, Fido2CredentialStore, Fido2UserInterface,
};

#[allow(missing_docs)]
#[derive(Clone)]
pub struct ClientFido2 {
    pub(crate) client: Client,
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error), uniffi(flat_error))]
pub enum DecryptFido2AutofillCredentialsError {
    #[error(transparent)]
    Fido2CredentialAutofillView(#[from] Fido2CredentialAutofillViewError),
}

impl ClientFido2 {
    #[allow(missing_docs)]
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    #[allow(missing_docs)]
    pub fn create_authenticator<'a>(
        &'a self,
        user_interface: &'a dyn Fido2UserInterface,
        credential_store: &'a dyn Fido2CredentialStore,
        options: Fido2AuthenticatorOptions,
    ) -> Fido2Authenticator<'a> {
        Fido2Authenticator::new(&self.client, user_interface, credential_store, options)
    }

    #[allow(missing_docs)]
    pub fn create_client<'a>(
        &'a self,
        user_interface: &'a dyn Fido2UserInterface,
        credential_store: &'a dyn Fido2CredentialStore,
    ) -> Fido2Client<'a> {
        Fido2Client {
            authenticator: self.create_authenticator(
                user_interface,
                credential_store,
                Fido2AuthenticatorOptions {
                    enable_hmac_secret: false,
                    external_encryption_key: None,
                },
            ),
        }
    }

    #[allow(missing_docs)]
    pub fn decrypt_fido2_autofill_credentials(
        &self,
        cipher_view: CipherView,
        encryption_key: Option<SymmetricCryptoKey>,
    ) -> Result<Vec<Fido2CredentialAutofillView>, DecryptFido2AutofillCredentialsError> {
        let key_store = self.client.internal.get_key_store();
        let mut ctx = key_store.context();
        let key_id = encryption_key.map(|key| ctx.add_local_symmetric_key(key.clone()));

        Ok(Fido2CredentialAutofillView::from_cipher_view(
            &cipher_view,
            &mut ctx,
            key_id,
        )?)
    }
}

#[allow(missing_docs)]
pub trait ClientFido2Ext {
    fn fido2(&self) -> ClientFido2;
}

impl ClientFido2Ext for Client {
    fn fido2(&self) -> ClientFido2 {
        ClientFido2::new(self.clone())
    }
}
