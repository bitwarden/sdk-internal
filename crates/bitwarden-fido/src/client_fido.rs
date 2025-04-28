use bitwarden_core::Client;
use bitwarden_vault::CipherView;
use thiserror::Error;

use crate::{
    Fido2Authenticator, Fido2Client, Fido2CredentialAutofillView, Fido2CredentialAutofillViewError,
    Fido2CredentialStore, Fido2UserInterface,
};

#[derive(Clone)]
pub struct ClientFido2 {
    pub(crate) client: Client,
}

#[derive(Debug, Error)]
pub enum DecryptFido2AutofillCredentialsError {
    #[error(transparent)]
    VaultLocked(#[from] bitwarden_core::VaultLockedError),
    #[error(transparent)]
    Fido2CredentialAutofillViewError(#[from] Fido2CredentialAutofillViewError),
}

impl ClientFido2 {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub fn create_authenticator<'a>(
        &'a self,
        user_interface: &'a dyn Fido2UserInterface,
        credential_store: &'a dyn Fido2CredentialStore,
    ) -> Fido2Authenticator<'a> {
        Fido2Authenticator::new(&self.client, user_interface, credential_store)
    }

    pub fn create_client<'a>(
        &'a self,
        user_interface: &'a dyn Fido2UserInterface,
        credential_store: &'a dyn Fido2CredentialStore,
    ) -> Fido2Client<'a> {
        Fido2Client {
            authenticator: self.create_authenticator(user_interface, credential_store),
        }
    }

    pub fn decrypt_fido2_autofill_credentials(
        &self,
        cipher_view: CipherView,
    ) -> Result<Vec<Fido2CredentialAutofillView>, DecryptFido2AutofillCredentialsError> {
        let key_store = self.client.internal.get_key_store();

        Ok(Fido2CredentialAutofillView::from_cipher_view(
            &cipher_view,
            &mut key_store.context(),
        )?)
    }
}

pub trait ClientFido2Ext {
    fn fido2(&self) -> ClientFido2;
}

impl ClientFido2Ext for Client {
    fn fido2(&self) -> ClientFido2 {
        ClientFido2::new(self.clone())
    }
}
