use super::{
    generate_fingerprint::{generate_fingerprint, generate_user_fingerprint},
    get_user_api_key, FingerprintRequest, FingerprintResponse, SecretVerificationRequest,
    UserApiKeyResponse,
};
use crate::{error::Result, Client};

/// A struct containing platform utilities.
pub struct ClientPlatform<'a> {
    pub(crate) client: &'a Client,
}

impl<'a> ClientPlatform<'a> {
    /// Will generate a fingerprint based on the `input`. Given the same `input` This
    /// method will always result in the exact same output.
    ///
    /// # Examples
    /// ```rust
    /// # use bitwarden_core::client::test_accounts::PUBLIC_KEY;
    /// use base64::{engine::general_purpose::STANDARD, Engine};
    /// use bitwarden_core::{Client, platform::FingerprintRequest};
    ///
    /// fn test(client: Client) {
    ///     let fingerprint_response = client.platform()
    ///         .fingerprint(&FingerprintRequest {
    ///             fingerprint_material: "my_material".to_owned(),
    ///             public_key: STANDARD.encode(PUBLIC_KEY),
    ///         })
    ///         .unwrap();
    ///
    ///     assert_eq!(fingerprint_response.fingerprint, "unsure-unethical-bruising-semester-subscript");
    /// }
    ///
    /// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(
    /// #   async { test(Client::test_account().await) });
    /// ```
    pub fn fingerprint(&self, input: &FingerprintRequest) -> Result<FingerprintResponse> {
        generate_fingerprint(input)
    }

    /// Will generate a fingerprint based on the given `fingerprint_material`
    /// and the users public key. Given the same `fingerprint_material` and
    /// the same user this method will always result in the exact same output.
    ///
    /// The returned fingerprint is a string of 5 words seperated by hyphens.
    ///
    /// # Examples
    /// ```rust
    /// use bitwarden_core::Client;
    ///
    /// async fn test() {
    ///     let client = Client::test_account().await;
    ///     let fingerprint = client.platform()
    ///         .user_fingerprint("my_material".to_owned())
    ///         .unwrap();
    ///
    ///     assert_eq!(fingerprint, "dreamland-desecrate-corrosive-ecard-retry");
    /// }
    /// ```
    pub fn user_fingerprint(self, fingerprint_material: String) -> Result<String> {
        generate_user_fingerprint(self.client, fingerprint_material)
    }

    pub async fn get_user_api_key(
        &mut self,
        input: SecretVerificationRequest,
    ) -> Result<UserApiKeyResponse> {
        get_user_api_key(self.client, &input).await
    }
}

impl<'a> Client {
    /// Retrieves a [`ClientPlatform`] for accessing Platform APIs.
    pub fn platform(&'a self) -> ClientPlatform<'a> {
        ClientPlatform { client: self }
    }
}
