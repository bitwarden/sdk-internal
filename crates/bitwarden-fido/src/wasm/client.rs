use bitwarden_vault::CipherView;
use wasm_bindgen::prelude::wasm_bindgen;

use super::{
    credential_store::{JsFido2CredentialStore, RawJsFido2CredentialStore},
    user_interface::{JsFido2UserInterface, RawJsFido2UserInterface},
};
use crate::{
    ClientData, ClientFido2, CredentialsForAutofillError, DecryptFido2AutofillCredentialsError,
    Fido2ClientError, Fido2CredentialAutofillView, GetAssertionError, GetAssertionRequest,
    GetAssertionResult, MakeCredentialError, MakeCredentialRequest, MakeCredentialResult, Origin,
    PublicKeyCredentialAuthenticatorAssertionResponse,
    PublicKeyCredentialAuthenticatorAttestationResponse, SilentlyDiscoverCredentialsError,
};

/// FIDO2 credential provider operations.
#[wasm_bindgen(js_name = Fido2Client)]
pub struct WasmFido2Client(ClientFido2);

impl WasmFido2Client {
    /// Wrap a [ClientFido2] for the JavaScript boundary.
    pub fn new(client: ClientFido2) -> Self {
        Self(client)
    }
}

#[wasm_bindgen(js_class = Fido2Client)]
impl WasmFido2Client {
    /// Construct an authenticator bound to the given callbacks, for CTAP-level operations.
    ///
    /// Nothing here ties an instance to a single ceremony — the constraint comes from JavaScript.
    /// `user_interface` is a per-ceremony session object, so reusing one instance across ceremonies
    /// drives the wrong session. Construct one per ceremony.
    pub fn authenticator(
        &self,
        user_interface: RawJsFido2UserInterface,
        credential_store: RawJsFido2CredentialStore,
    ) -> WasmFido2Authenticator {
        WasmFido2Authenticator {
            client: self.0.clone(),
            user_interface: JsFido2UserInterface::new(user_interface),
            credential_store: JsFido2CredentialStore::new(credential_store),
        }
    }

    /// Construct a WebAuthn client bound to the given callbacks, for full ceremonies.
    pub fn client(
        &self,
        user_interface: RawJsFido2UserInterface,
        credential_store: RawJsFido2CredentialStore,
    ) -> WasmFido2WebAuthnClient {
        WasmFido2WebAuthnClient(self.authenticator(user_interface, credential_store))
    }

    /// Decrypt the FIDO2 credentials in a cipher into the form used for autofill.
    pub fn decrypt_fido2_autofill_credentials(
        &self,
        cipher_view: CipherView,
    ) -> Result<Vec<Fido2CredentialAutofillView>, DecryptFido2AutofillCredentialsError> {
        self.0.decrypt_fido2_autofill_credentials(cipher_view)
    }
}

/// CTAP-level FIDO2 operations.
#[wasm_bindgen(js_name = Fido2Authenticator)]
pub struct WasmFido2Authenticator {
    client: ClientFido2,
    user_interface: JsFido2UserInterface,
    credential_store: JsFido2CredentialStore,
}

impl WasmFido2Authenticator {
    /// Build a [crate::Fido2Authenticator] for a single call.
    ///
    /// [crate::Fido2Authenticator] borrows its callbacks, so it is constructed per call rather
    /// than stored: the borrow then lives and dies inside one method and its lifetime never has
    /// to escape into a field.
    fn create_authenticator(&self) -> crate::Fido2Authenticator<'_> {
        self.client
            .create_authenticator(&self.user_interface, &self.credential_store)
    }
}

#[wasm_bindgen(js_class = Fido2Authenticator)]
impl WasmFido2Authenticator {
    /// Create a new credential, as CTAP `authenticatorMakeCredential`.
    pub async fn make_credential(
        &self,
        request: MakeCredentialRequest,
    ) -> Result<MakeCredentialResult, MakeCredentialError> {
        self.create_authenticator().make_credential(request).await
    }

    /// Assert an existing credential, as CTAP `authenticatorGetAssertion`.
    pub async fn get_assertion(
        &self,
        request: GetAssertionRequest,
    ) -> Result<GetAssertionResult, GetAssertionError> {
        self.create_authenticator().get_assertion(request).await
    }

    /// List the credentials matching a relying party without prompting the user.
    pub async fn silently_discover_credentials(
        &self,
        rp_id: String,
        user_handle: Option<Vec<u8>>,
    ) -> Result<Vec<Fido2CredentialAutofillView>, SilentlyDiscoverCredentialsError> {
        self.create_authenticator()
            .silently_discover_credentials(rp_id, user_handle)
            .await
    }

    /// List every credential in the vault that can be offered for autofill.
    pub async fn credentials_for_autofill(
        &self,
    ) -> Result<Vec<Fido2CredentialAutofillView>, CredentialsForAutofillError> {
        self.create_authenticator().credentials_for_autofill().await
    }
}

/// WebAuthn-level FIDO2 ceremonies.
#[wasm_bindgen(js_name = Fido2WebAuthnClient)]
pub struct WasmFido2WebAuthnClient(WasmFido2Authenticator);

#[wasm_bindgen(js_class = Fido2WebAuthnClient)]
impl WasmFido2WebAuthnClient {
    /// Run a full WebAuthn registration ceremony.
    pub async fn register(
        &self,
        origin: Origin,
        request: String,
        client_data: ClientData,
    ) -> Result<PublicKeyCredentialAuthenticatorAttestationResponse, Fido2ClientError> {
        self.0
            .client
            .create_client(&self.0.user_interface, &self.0.credential_store)
            .register(origin, request, client_data)
            .await
    }

    /// Run a full WebAuthn authentication ceremony.
    pub async fn authenticate(
        &self,
        origin: Origin,
        request: String,
        client_data: ClientData,
    ) -> Result<PublicKeyCredentialAuthenticatorAssertionResponse, Fido2ClientError> {
        self.0
            .client
            .create_client(&self.0.user_interface, &self.0.credential_store)
            .authenticate(origin, request, client_data)
            .await
    }
}
