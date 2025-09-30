use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    PassphraseError, PassphraseGeneratorRequest, PasswordError, PasswordGeneratorRequest,
    UsernameError, UsernameGeneratorRequest, passphrase::passphrase, password::password,
    username::username,
};

#[allow(missing_docs)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct GeneratorClient {
    client: Client,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl GeneratorClient {
    fn new(client: Client) -> Self {
        Self { client }
    }

    /// Generates a random password.
    ///
    /// The character sets and password length can be customized using the `input` parameter.
    ///
    /// # Examples
    ///
    /// ```
    /// use bitwarden_core::Client;
    /// use bitwarden_generators::{GeneratorClientsExt, PassphraseError, PasswordGeneratorRequest};
    ///
    /// async fn test() -> Result<(), PassphraseError> {
    ///     let input = PasswordGeneratorRequest {
    ///         lowercase: true,
    ///         uppercase: true,
    ///         numbers: true,
    ///         length: 20,
    ///         ..Default::default()
    ///     };
    ///     let password = Client::new(None).generator().password(input).unwrap();
    ///     println!("{}", password);
    ///     Ok(())
    /// }
    /// ```
    pub fn password(&self, input: PasswordGeneratorRequest) -> Result<String, PasswordError> {
        password(input)
    }

    /// Generates a random passphrase.
    /// A passphrase is a combination of random words separated by a character.
    /// An example of passphrase is `correct horse battery staple`.
    ///
    /// The number of words and their case, the word separator, and the inclusion of
    /// a number in the passphrase can be customized using the `input` parameter.
    ///
    /// # Examples
    ///
    /// ```
    /// use bitwarden_core::Client;
    /// use bitwarden_generators::{GeneratorClientsExt, PassphraseError, PassphraseGeneratorRequest};
    ///
    /// async fn test() -> Result<(), PassphraseError> {
    ///     let input = PassphraseGeneratorRequest {
    ///         num_words: 4,
    ///         ..Default::default()
    ///     };
    ///     let passphrase = Client::new(None).generator().passphrase(input).unwrap();
    ///     println!("{}", passphrase);
    ///     Ok(())
    /// }
    /// ```
    pub fn passphrase(&self, input: PassphraseGeneratorRequest) -> Result<String, PassphraseError> {
        passphrase(input)
    }
}

impl GeneratorClient {
    /// Generates a random username.
    /// There are different username generation strategies, which can be customized using the
    /// `input` parameter.
    ///
    /// Note that most generation strategies will be executed on the client side, but `Forwarded`
    /// will use third-party services, which may require a specific setup or API key.
    ///
    /// ```
    /// use bitwarden_core::Client;
    /// use bitwarden_generators::{GeneratorClientsExt, UsernameError, UsernameGeneratorRequest};
    ///
    /// async fn test() -> Result<(), UsernameError> {
    ///     let input = UsernameGeneratorRequest::Word {
    ///         capitalize: true,
    ///         include_number: true,
    ///     };
    ///     let username = Client::new(None).generator().username(input).await.unwrap();
    ///     println!("{}", username);
    ///     Ok(())
    /// }
    /// ```
    pub async fn username(&self, input: UsernameGeneratorRequest) -> Result<String, UsernameError> {
        username(input, self.client.internal.get_http_client()).await
    }
}

#[allow(missing_docs)]
pub trait GeneratorClientsExt {
    fn generator(&self) -> GeneratorClient;
}

impl GeneratorClientsExt for Client {
    fn generator(&self) -> GeneratorClient {
        GeneratorClient::new(self.clone())
    }
}
