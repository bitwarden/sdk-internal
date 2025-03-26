use std::rc::Rc;

use bitwarden_core::Client;
use bitwarden_generators::{GeneratorClientsExt, PasswordGeneratorRequest, PassphraseGeneratorRequest};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct GeneratorClient(Rc<Client>);

impl GeneratorClient {
    /// Constructs a new SDK client for generating random passwords and passphrases
    ///
    /// # Arguments
    /// - `client` - The client used to access the SDK
    ///
    /// # Returns
    /// - `Self` - Returns newly constructed client
    pub fn new(client: Rc<Client>) -> Self {
        Self(client)
    }
}

#[wasm_bindgen]
impl GeneratorClient {
    /// Generates a password from a provided request
    ///
    /// # Arguments
    /// - `request` - Settings for the character sets and password length
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
    /// - `request` - Settings for the word count, word separators character sets
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
