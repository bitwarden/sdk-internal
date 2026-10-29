//! The organization's key pair, held in a key store context.
//!
//! The organization's private key is stored wrapped with the organization key.
//! [`OrganizationPrivateKey`] unwraps it into the key store context, to encapsulate keys to the
//! organization and to open keys that were encapsulated to it.

use bitwarden_crypto::{
    CryptoError, EncString, KeySlotIds, KeyStoreContext, PublicKey, UnsignedSharedKey,
};
use thiserror::Error;

use crate::trust_proof::{CryptographicProof, TrustProof};

/// Errors that can occur when unwrapping the organization's private key.
#[derive(Debug, Error)]
pub enum OrganizationPrivateKeyUnwrapError {
    /// The wrapped private key belongs to a different organization key, or the stored value is
    /// corrupt.
    #[error("The organization's private key could not be unwrapped with the organization key")]
    UnwrapFailed,
}

/// Errors that can occur when deriving the organization's public key.
#[derive(Debug, Error)]
pub enum OrganizationPublicKeyError {
    /// The private key of [`OrganizationPrivateKey`] is not in the key store context.
    #[error("The organization's private key does not exist in the key store context")]
    MissingPrivateKey,
}

/// The organization's private key, unwrapped into the key store context.
pub struct OrganizationPrivateKey<Ids: KeySlotIds> {
    private_key_id: Ids::Private,
}

impl<Ids: KeySlotIds> OrganizationPrivateKey<Ids> {
    /// Unwraps the organization's private key with the organization key.
    ///
    /// `wrapped_organization_private_key` is the wrapped private key shared with the server.
    pub fn unwrap_with_organization_key(
        organization_key: Ids::Symmetric,
        wrapped_organization_private_key: &EncString,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Self, OrganizationPrivateKeyUnwrapError> {
        let private_key_id = ctx
            .unwrap_private_key(organization_key, wrapped_organization_private_key)
            .map_err(|_| OrganizationPrivateKeyUnwrapError::UnwrapFailed)?;

        Ok(Self { private_key_id })
    }

    /// The organization's public key.
    pub fn public_key(
        &self,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<PublicKey, OrganizationPublicKeyError> {
        ctx.get_public_key(self.private_key_id)
            .map_err(|_| OrganizationPublicKeyError::MissingPrivateKey)
    }

    /// The proof that the organization's public key is trusted: the caller holds the private key.
    pub fn trust_proof(&self) -> TrustProof<Ids> {
        TrustProof::CryptographicallyTrusted(CryptographicProof::OwnPrivateKey(self.private_key_id))
    }

    /// Opens a key that was encapsulated to the organization, returning the id it was added to the
    /// context under.
    pub(crate) fn decapsulate_key(
        &self,
        encapsulated_key: &UnsignedSharedKey,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, CryptoError> {
        encapsulated_key.decapsulate(self.private_key_id, ctx)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{
        KeyStore, PublicKeyEncryptionAlgorithm, SpkiPublicKeyBytes,
        SymmetricKeyAlgorithm::Aes256CbcHmac,
    };
    use bitwarden_encoding::B64;

    use super::*;
    use crate::test_support::{
        TEST_VECTOR_V1_WRAPPED_PRIVATE_KEY, TestIds, TestSymmKey, load_v1_test_vectors,
        unwrap_v1_organization_private_key,
    };

    /// The public key of the pinned organization private key, as base64 SPKI.
    const TEST_VECTOR_ORGANIZATION_PUBLIC_KEY: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoNoakr8gAXszoM1FQ1kz3rCXbd/ROcb8JQveiAmYuSCvA3Wx8zLqmYo0Jq6C3gPGxCHLVI4pYA6Pt0M59AlvK4jOiGwSPh1Wt6M+HlGUuBkW3Q3fJ0OwwKDT0WwzuZlmateoxg1Jq91jaVevc7bfsJMD8YFIY/c5nWTWIs5HG/v8ZwQMrdqAO/f7O3SJ4SvetkZqQynbTAL7AfPSVhIQt85mxyvkcAsqnwnmqjmlZsSXas2Ghp9v/5Y1eyLEgNUHyFghrNqbm99LTWnwgUVPhx8ALPkI2H8r4MMEPidZ1vEFURpL513nvFYTqfe2Vzg6JUXNu0w8ikFZh/6CNeXLTQIDAQAB";

    #[test]
    fn test_unwrapping_with_the_wrong_organization_key_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = load_v1_test_vectors(&mut ctx);
        let other_organization_key = ctx.make_symmetric_key(Aes256CbcHmac);

        let result = OrganizationPrivateKey::unwrap_with_organization_key(
            other_organization_key,
            &wrapped_private_key,
            &mut ctx,
        );

        assert!(matches!(
            result,
            Err(OrganizationPrivateKeyUnwrapError::UnwrapFailed)
        ));
    }

    #[test]
    fn test_public_key_in_another_context_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = load_v1_test_vectors(&mut ctx);
        let organization_private_key = OrganizationPrivateKey::unwrap_with_organization_key(
            TestSymmKey::Organization,
            &wrapped_private_key,
            &mut ctx,
        )
        .unwrap();
        let other_key_store = KeyStore::<TestIds>::default();
        let other_ctx = other_key_store.context();

        let result = organization_private_key.public_key(&other_ctx);

        assert!(matches!(
            result,
            Err(OrganizationPublicKeyError::MissingPrivateKey)
        ));
    }

    #[test]
    fn test_unwrapping_a_wrapped_value_that_is_not_a_private_key_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        load_v1_test_vectors(&mut ctx);
        let symmetric_key = ctx.make_symmetric_key(Aes256CbcHmac);
        let wrapped_symmetric_key = ctx
            .wrap_symmetric_key(TestSymmKey::Organization, symmetric_key)
            .unwrap();

        let result = OrganizationPrivateKey::unwrap_with_organization_key(
            TestSymmKey::Organization,
            &wrapped_symmetric_key,
            &mut ctx,
        );

        assert!(matches!(
            result,
            Err(OrganizationPrivateKeyUnwrapError::UnwrapFailed)
        ));
    }

    #[test]
    fn test_unwrapping_with_a_missing_organization_key_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key: EncString = TEST_VECTOR_V1_WRAPPED_PRIVATE_KEY.parse().unwrap();

        let result = OrganizationPrivateKey::unwrap_with_organization_key(
            TestSymmKey::Organization,
            &wrapped_private_key,
            &mut ctx,
        );

        assert!(matches!(
            result,
            Err(OrganizationPrivateKeyUnwrapError::UnwrapFailed)
        ));
    }

    #[test]
    fn test_trust_proof_verifies_the_organization_public_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_private_key = unwrap_v1_organization_private_key(&mut ctx);
        let organization_public_key = organization_private_key.public_key(&ctx).unwrap();

        let result = organization_private_key
            .trust_proof()
            .verify(&organization_public_key, &ctx);

        assert!(matches!(result, Ok(())));
    }

    #[test]
    fn test_decapsulating_a_key_encapsulated_to_the_organization_public_key_opens_the_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_private_key = unwrap_v1_organization_private_key(&mut ctx);
        let symmetric_key = ctx.make_symmetric_key(Aes256CbcHmac);
        let encapsulated_key = UnsignedSharedKey::encapsulate(
            symmetric_key,
            &organization_private_key.public_key(&ctx).unwrap(),
            &ctx,
        )
        .unwrap();

        let decapsulated_key = organization_private_key
            .decapsulate_key(&encapsulated_key, &mut ctx)
            .unwrap();

        ctx.assert_symmetric_keys_equal(symmetric_key, decapsulated_key);
    }

    #[test]
    fn test_decapsulating_with_a_non_matching_private_key_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_private_key = unwrap_v1_organization_private_key(&mut ctx);
        let other_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let symmetric_key = ctx.make_symmetric_key(Aes256CbcHmac);
        let encapsulated_key = UnsignedSharedKey::encapsulate(
            symmetric_key,
            &ctx.get_public_key(other_private_key).unwrap(),
            &ctx,
        )
        .unwrap();

        let result = organization_private_key.decapsulate_key(&encapsulated_key, &mut ctx);

        assert!(matches!(result, Err(CryptoError::KeyDecrypt)));
    }

    #[test]
    fn test_decapsulating_in_another_context_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_private_key = unwrap_v1_organization_private_key(&mut ctx);
        let symmetric_key = ctx.make_symmetric_key(Aes256CbcHmac);
        let encapsulated_key = UnsignedSharedKey::encapsulate(
            symmetric_key,
            &organization_private_key.public_key(&ctx).unwrap(),
            &ctx,
        )
        .unwrap();
        let other_key_store = KeyStore::<TestIds>::default();
        let mut other_ctx = other_key_store.context_mut();

        let result = organization_private_key.decapsulate_key(&encapsulated_key, &mut other_ctx);

        assert!(matches!(result, Err(CryptoError::MissingKeyId(_))));
    }

    #[test]
    #[ignore = "Manual test to generate test vectors"]
    fn generate_test_vectors() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = load_v1_test_vectors(&mut ctx);
        let organization_private_key = OrganizationPrivateKey::unwrap_with_organization_key(
            TestSymmKey::Organization,
            &wrapped_private_key,
            &mut ctx,
        )
        .unwrap();

        let public_key = organization_private_key.public_key(&ctx).unwrap();

        println!(
            "const TEST_VECTOR_ORGANIZATION_PUBLIC_KEY: &str = \"{}\";",
            B64::from(public_key.to_der().unwrap())
        );
    }

    #[test]
    fn test_organization_private_key_test_vector() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = load_v1_test_vectors(&mut ctx);

        let organization_private_key = OrganizationPrivateKey::unwrap_with_organization_key(
            TestSymmKey::Organization,
            &wrapped_private_key,
            &mut ctx,
        )
        .unwrap();

        let expected = SpkiPublicKeyBytes::from(
            B64::try_from(TEST_VECTOR_ORGANIZATION_PUBLIC_KEY)
                .unwrap()
                .as_bytes()
                .to_vec(),
        );
        assert_eq!(
            organization_private_key
                .public_key(&ctx)
                .unwrap()
                .to_der()
                .unwrap(),
            expected
        );
    }
}
