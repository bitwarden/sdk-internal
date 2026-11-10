#![doc = include_str!("../README.md")]

uniffi::setup_scaffolding!();

mod error;

use std::str::FromStr;

use bitwarden_crypto::{EncString, safe::SymmetricKeyEnvelope};
pub use error::ServerError;

/// Entry point of the server bindings.
///
/// Stateless: the server can share one instance across threads.
#[derive(uniffi::Object, Default)]
pub struct ServerClient;

#[uniffi::export]
impl ServerClient {
    /// Creates a new client.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self
    }

    /// The SDK version this library was built from.
    pub fn version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    /// The id of the key `enc_string` was encrypted with, as 32 lowercase hex characters.
    ///
    /// [None] for legacy (non-COSE) EncStrings, which carry no key id.
    pub fn get_encrypted_by_key_id_encstring(
        &self,
        enc_string: String,
    ) -> Result<Option<String>, ServerError> {
        let enc_string =
            EncString::parse_strict(&enc_string).map_err(ServerError::InvalidEncString)?;

        Ok(enc_string.key_id().map(|id| id.to_string()))
    }

    /// The id of the key sealed in `envelope`, as 32 lowercase hex characters.
    ///
    /// [None] if the envelope carries no key id.
    pub fn get_encrypted_by_key_id_symmetrickeyenvelope(
        &self,
        envelope: String,
    ) -> Result<Option<String>, ServerError> {
        let envelope =
            SymmetricKeyEnvelope::from_str(&envelope).map_err(ServerError::InvalidEnvelope)?;
        let key_id = envelope
            .contained_key_id()
            .map_err(ServerError::InvalidEnvelope)?;

        Ok(key_id.map(|id| id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{
        KeyStore, PrimitiveEncryptable, SymmetricKeyAlgorithm, key_slot_ids,
        safe::{SymmetricKeyEnvelope, SymmetricKeyEnvelopeNamespace},
    };

    use super::*;

    key_slot_ids! {
        #[symmetric]
        pub enum TestSymmKey {
            #[local]
            Local(LocalId),
        }

        #[private]
        pub enum TestPrivateKey {
            #[local]
            Local(LocalId),
        }

        #[signing]
        pub enum TestSigningKey {
            #[local]
            Local(LocalId),
        }

        pub TestIds => TestSymmKey, TestPrivateKey, TestSigningKey;
    }

    // Fixed inputs, mirrored in the dotnet-extensions tests. `COSE_ENCSTRING` is encrypted with,
    // and `ENVELOPE` seals, the XChaCha20-Poly1305 key `FIXTURE_KEY_ID`.
    const FIXTURE_KEY_ID: &str = "5367fc06796da8e62b61afdc5c02b9f1";
    const COSE_ENCSTRING: &str = "7.g1g/owE6AAERbwN4I2FwcGxpY2F0aW9uL3guYml0d2FyZGVuLnV0ZjgtcGFkZGVkBFBTZ/wGeW2o5ithr9xcArnxoQVYGK4ToRVEH/cowcY3KzAn0K4jqgl06xAWpVgwY5qRRgNeYMc9KUbZmghWPKJAz10ENbQdS0/u0XeWRDQz5TRXJiNl+TDyrlI6731b";
    const LEGACY_ENCSTRING: &str = "2.lydV844NLeMlZyw+lBvavQ==|g/ybWBsaTkyTDJYL1kcrZQ==|2ZeoX1YiRQoaowBuGS7feAH9PZvz3VDy6QuPtMNu7R4=";
    const ENVELOPE: &str = "g1g+pgE6AAEReQMYZQRQNPLyvvUn/ZOFjUStHRQPvzoAARVcUFNn/AZ5bajmK2Gv3FwCufE6AAE4gQM6AAE4gAKhBVgYqKO9y+PFmZQr6GR5Nmj5bzc1uvqHm4FTWFRUAxgMKOBrC0T0iM0bqLFjzmBCkXA6fJ9qzG6e2iIWW4mJ7/j1+T/90Yi6syHtD+5mvda+rg6BF+BLzB48oItIfasxUcYthwzxVW33CfVk/JoNU+U=";

    #[test]
    fn fixtures_return_expected_key_ids() {
        let client = ServerClient::new();
        let expected = Some(FIXTURE_KEY_ID.to_string());

        let cose = client.get_encrypted_by_key_id_encstring(COSE_ENCSTRING.into());
        let legacy = client.get_encrypted_by_key_id_encstring(LEGACY_ENCSTRING.into());
        let envelope = client.get_encrypted_by_key_id_symmetrickeyenvelope(ENVELOPE.into());

        assert_eq!(cose.expect("valid"), expected);
        assert_eq!(legacy.expect("valid"), None);
        assert_eq!(envelope.expect("valid"), expected);
    }

    #[test]
    fn version_is_crate_version() {
        assert_eq!(ServerClient::new().version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn encstring_key_id_matches_encrypting_key() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let expected = ctx.get_symmetric_key_id(key).map(|id| id.to_string());

        let enc_string = "secret".encrypt(&mut ctx, key).expect("encrypts");
        let actual = ServerClient::new()
            .get_encrypted_by_key_id_encstring(enc_string.to_string())
            .expect("valid EncString");

        assert!(expected.is_some());
        assert_eq!(actual, expected);
    }

    #[test]
    fn encstring_legacy_has_no_key_id() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

        let enc_string = "secret".encrypt(&mut ctx, key).expect("encrypts");
        let actual = ServerClient::new()
            .get_encrypted_by_key_id_encstring(enc_string.to_string())
            .expect("valid EncString");

        assert_eq!(actual, None);
    }

    #[test]
    fn encstring_invalid_is_error() {
        let result = ServerClient::new().get_encrypted_by_key_id_encstring("garbage".into());

        assert!(matches!(result, Err(ServerError::InvalidEncString(_))));
    }

    #[test]
    fn envelope_key_id_matches_sealed_key() {
        let store = KeyStore::<TestIds>::default();
        let mut ctx = store.context_mut();
        let sealed = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrapping = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let expected = ctx.get_symmetric_key_id(sealed).map(|id| id.to_string());

        let envelope = SymmetricKeyEnvelope::seal(
            sealed,
            wrapping,
            SymmetricKeyEnvelopeNamespace::OrganizationInvite,
            &ctx,
        )
        .expect("seals");
        let actual = ServerClient::new()
            .get_encrypted_by_key_id_symmetrickeyenvelope(String::from(envelope))
            .expect("valid envelope");

        assert!(expected.is_some());
        assert_eq!(actual, expected);
    }

    #[test]
    fn envelope_invalid_is_error() {
        let result =
            ServerClient::new().get_encrypted_by_key_id_symmetrickeyenvelope("garbage".into());

        assert!(matches!(result, Err(ServerError::InvalidEnvelope(_))));
    }
}
