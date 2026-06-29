use bitwarden_core::{Client, FromClient, key_management::KeySlotIds};
use bitwarden_crypto::{Kdf, KeyStore};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

/// Tells you which cryptographic algorithms to use for the current account and environment.
///
/// Some environments are restricted in which algorithms they may use — for example, government
/// (FedRAMP) deployments must use FIPS-approved algorithms. Ask this client which algorithm to use
/// instead of picking one yourself, so the choice stays correct as those rules change.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct CryptoCipherSuiteClient {
    pub(crate) key_store: KeyStore<KeySlotIds>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CryptoCipherSuiteClient {
    /// Returns the KDF a new account should use in the current environment.
    ///
    /// In a FIPS (gov) environment the FIPS-approved PBKDF2 is used; otherwise the modern Argon2id
    /// default.
    pub fn default_kdf_for_new_account(&self) -> Kdf {
        self.key_store
            .context()
            .cipher_suite()
            .default_kdf_for_new_account()
    }

    /// Returns whether the given KDF is allowed in the current environment.
    ///
    /// Intended for surfaces that let a user pick a KDF (e.g. the Change KDF settings screen): the
    /// caller can validate or filter the options it offers. In a FIPS (gov) environment only PBKDF2
    /// is allowed; otherwise every supported KDF is allowed.
    pub fn is_kdf_compliant(&self, kdf: Kdf) -> bool {
        self.key_store
            .context()
            .cipher_suite()
            .is_kdf_compliant(&kdf)
    }
}

/// Extension trait that exposes [`CryptoCipherSuiteClient`] on [`Client`].
pub trait CryptoCipherSuiteClientExt {
    /// Returns a [`CryptoCipherSuiteClient`] for the current environment.
    fn crypto_cipher_suite(&self) -> CryptoCipherSuiteClient;
}

impl CryptoCipherSuiteClientExt for Client {
    fn crypto_cipher_suite(&self) -> CryptoCipherSuiteClient {
        CryptoCipherSuiteClient::from_client(self)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::{Client, ClientSettings};
    use bitwarden_crypto::CipherSuite;

    use super::*;

    fn client_with_suite(cipher_suite: CipherSuite) -> Client {
        let client = Client::new(Some(ClientSettings::default()));
        client
            .internal
            .get_key_store()
            .set_cipher_suite(cipher_suite);
        client
    }

    #[test]
    fn default_kdf_for_new_account_is_argon2_under_standard() {
        let kdf = client_with_suite(CipherSuite::Standard)
            .crypto_cipher_suite()
            .default_kdf_for_new_account();
        assert!(matches!(kdf, Kdf::Argon2id { .. }));
    }

    #[test]
    fn default_kdf_for_new_account_is_pbkdf2_under_fips() {
        let kdf = client_with_suite(CipherSuite::Fips)
            .crypto_cipher_suite()
            .default_kdf_for_new_account();
        assert!(matches!(kdf, Kdf::PBKDF2 { .. }));
    }

    #[test]
    fn every_kdf_is_compliant_under_standard() {
        let client = client_with_suite(CipherSuite::Standard).crypto_cipher_suite();
        assert!(client.is_kdf_compliant(Kdf::default_argon2()));
        assert!(client.is_kdf_compliant(Kdf::default_pbkdf2()));
    }

    #[test]
    fn only_pbkdf2_is_compliant_under_fips() {
        let client = client_with_suite(CipherSuite::Fips).crypto_cipher_suite();
        assert!(client.is_kdf_compliant(Kdf::default_pbkdf2()));
        assert!(!client.is_kdf_compliant(Kdf::default_argon2()));
    }
}
