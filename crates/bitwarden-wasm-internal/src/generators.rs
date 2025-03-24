use std::rc::Rc;

use bitwarden_core::Client;
use bitwarden_generators::{GeneratorClientsExt, PasswordGeneratorRequest, PassphraseGeneratorRequest};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct GeneratorClient(Rc<Client>);

impl GeneratorClient {
    pub fn new(client: Rc<Client>) -> Self {
        Self(client)
    }
}

#[wasm_bindgen]
impl GeneratorClient {
    /// Generates a password from a provided request
    ///
    /// # Arguments
    /// - `request` - PasswordGeneratorRequest
    ///
    /// # Returns
    /// - `Ok(String)` containing the generated password
    /// - `Err(PasswordError)` if password generation fails
    pub fn generate_password(
        &self,
        request: PasswordGeneratorRequest,
    ) -> Result<String, bitwarden_generators::PasswordError> {
        self.0.generator().password(request)
    }

    /// Generates a passphrase from a provided request
    ///
    /// # Arguments
    /// - `request` - PassphraseGeneratorRequest
    ///
    /// # Returns
    /// - `Ok(String)` containing the generated passphrase
    /// - `Err(PassphraseError)` if passphrase generation fails
    pub fn generate_passphrase(
        &self,
        request: PassphraseGeneratorRequest,
    ) -> Result<String, bitwarden_generators::PassphraseError> {
        self.0.generator().passphrase(request)
    }
}