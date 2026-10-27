//! The organization's key pair, held in a key store context.
//!
//! The organization's private key is stored wrapped with the organization key. Unwrapping it
//! gives a handle that encapsulates keys to the organization, and opens keys that were
//! encapsulated to it.
//!
//! The organization's identity replaces this type. It adds the organization's signing key,
//! and is shaped like the user's account cryptographic state.

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
    /// The handle is used with a key store context other than the one it was unwrapped into.
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
        KeyStore, SpkiPublicKeyBytes, SymmetricCryptoKey, SymmetricKeyAlgorithm::Aes256CbcHmac,
        key_slot_ids,
    };
    use bitwarden_encoding::B64;

    use super::*;

    const TEST_VECTOR_ORG_KEY: &str =
        "KGP9Nc2/91w+42Z9VzY0m7h18avuZcq4ICM8Rhdc3BD92LbWS2TQkVBzavvUM684WKXiC22NJi2EwaiDW4YTAA==";
    /// The organization private key, wrapped with [`TEST_VECTOR_ORG_KEY`].
    const TEST_VECTOR_WRAPPED_PRIVATE_KEY: &str = "2.bi9TWF/zrujUg1y+v8ECtQ==|kEMkuRt42j65YZnPEc4bLOT0/WDZwWSNJNGlUMdr/LRF3qi/vCnZ7eT0+7MruTccmyoAjKmsXdoBcufrOdPBUguFQn1LQMGqHqCyyB3SIijOlLyOOmxWYqoLUjihy8o8URGWjrAGWZnkeYWHTlFZP09Fag2xCwiQ/qS32Q+qTGGHDs0FiwjplcPkW9knlmgCXbuyPqDnEYoa0Qs/CC1hUCzFFrWs7QkE+5eLaNHxuBPpsrY6y795kEu9ve38F3piY9b6lQpc/iPGv8Zfh1isI7Mpy1zMwntXGSHjUOy17nPxCqkgYufuNGnwGNwsGjkLAl7e7bD39SYfEpTDaRUgmTl8UrZDx274e6Um1LLvokf3HiL1tboJ9/TW8IiMuAdrb3PLTH6Sep8lqZ3WhNADfMMJle9kCojHp6XSB14in1JqP0636exYeJu+FhUC1TfrthuQN2QDQ8LAvgZR7YvzkTJX3Sc5jP7m/yCmCbHhIqIAaGqJsRwAee0EMsKcALz3/akVoyjHU2LHD3dzQnyMyszyRNYViBNYAM9qBN2DqwWRDOtM171xNVJcTFsAh4mBSLiLOlDsXqLqHVKu2VJNE1XhTQ5Szubqefa/Or7nfxXcxDvivqZ7d5NfDFEskUMqh5yq1KoLK0oK5c+KvY/COIZr/kct+qtfZsXo3w5xJnPOqrAKGm+9CF4OINpLM8Z3csdZf9l5XjlmO1kIuBbquQZ0EZCHzD/GEfXRGB8BEkugdTfpnTDtmmuAJXkIY6t6e6pRUU9u4/sl+U7Iuh22fOA59SuQOElr5Lxre+hQBrRfJS3tSMEtMjYhVmltrngH+SLRxMxH/evbe2uvNaaxlFJe6EK1vqchyTX6nM8Z+2Yjb5pOAzrKQYqwwmVys9IHfjXhybqv10gFpDXBE/eq8u9xs9LbQQ03EbveQUtqdh/ms8SxLOQA9Sm9JwHEL0Zni+8NdAa5orDYzOi53bQLgrs+uUldgB/KOW2goTnKGm4YTbMAXEbum8pST8EXB9jNDXyofyN8IQUoLRvVkEgzbSPBS1sYpkkKdLZy3ojOCKnMnHXIVtzJojFckiutbj6d927X5w51E/RDMoAdylGRVKnmqLKysFRqL+pZK8Cyo+ECr7notG8kr7pVnofzigjKZS9qkRmqEa9bju1GgI20g4cxro8/0O0XnU1o0Mx46qH3niORY59i5bdMwaDS6H2c6+rmf9bIFwwgyAZvHlVdcGNoBGPR3ZXHThwI1OmWSslLWVW0IaS4utB1jL4zvHPCqh/ButA8HeRmU/NYSfaqb9YXyzn+C7ED15MWXkYmZzeE38HHxhqs12+oj+WFcg4d5/e2UcccuVi36SWhA0xWk8Kk2D6e1Pz1lmaw20vpb0eUq4AS5ZnMmWTEiKORFeGNTIROq9vuPuitLrREedu9PGjf5aeKcNqlq2nr7fOaxyi2ocKs7pLqVBUH1G7zHpCo3Rt1+o18guXFHT56vQFfkzoUNXiS6TRM4Mkl3s0TyGgBhxZkNJleTI6y4xhfH1iathBnLcfelLbxZhDB1wh3RXowS32jpM/J4pSUuNEmSLSqRQtRJY41BG00nYY02qEbakkgk6pS6a0/CWphyLfHAzUWbabOhqR1iPN9/ZiecjI=|eoklmBw+LYy2NNwjLOuA4+szKH5SzLGPlrhIJ/vfmW4=";

    /// The public key of the pinned organization private key, as base64 SPKI.
    const TEST_VECTOR_ORGANIZATION_PUBLIC_KEY: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoNoakr8gAXszoM1FQ1kz3rCXbd/ROcb8JQveiAmYuSCvA3Wx8zLqmYo0Jq6C3gPGxCHLVI4pYA6Pt0M59AlvK4jOiGwSPh1Wt6M+HlGUuBkW3Q3fJ0OwwKDT0WwzuZlmateoxg1Jq91jaVevc7bfsJMD8YFIY/c5nWTWIs5HG/v8ZwQMrdqAO/f7O3SJ4SvetkZqQynbTAL7AfPSVhIQt85mxyvkcAsqnwnmqjmlZsSXas2Ghp9v/5Y1eyLEgNUHyFghrNqbm99LTWnwgUVPhx8ALPkI2H8r4MMEPidZ1vEFURpL513nvFYTqfe2Vzg6JUXNu0w8ikFZh/6CNeXLTQIDAQAB";

    fn add_symmetric_key(key: &str, ctx: &mut KeyStoreContext<'_, TestIds>) -> TestSymmKey {
        ctx.add_local_symmetric_key(
            SymmetricCryptoKey::try_from(B64::try_from(key).unwrap()).unwrap(),
        )
    }

    /// Loads the organization key into the `Organization` slot and returns the wrapped
    /// organization private key.
    fn load_test_vectors(ctx: &mut KeyStoreContext<'_, TestIds>) -> EncString {
        let org_key = add_symmetric_key(TEST_VECTOR_ORG_KEY, ctx);
        ctx.persist_symmetric_key(org_key, TestSymmKey::Organization)
            .unwrap();
        TEST_VECTOR_WRAPPED_PRIVATE_KEY.parse().unwrap()
    }

    #[test]
    fn test_unwrapping_with_the_wrong_organization_key_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = load_test_vectors(&mut ctx);
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
        let wrapped_private_key = load_test_vectors(&mut ctx);
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
    #[ignore = "Manual test to generate test vectors"]
    fn generate_test_vectors() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = load_test_vectors(&mut ctx);
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
        let wrapped_private_key = load_test_vectors(&mut ctx);

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
    key_slot_ids! {
        #[symmetric]
        pub enum TestSymmKey {
            Organization,
            #[local]
            Local(LocalId),
        }

        #[private]
        pub enum TestPrivateKey {
            Organization,
            #[local]
            Local(LocalId),
        }

        #[signing]
        pub enum TestSigningKey {
            Organization,
            #[local]
            Local(LocalId),
        }

        pub TestIds => TestSymmKey, TestPrivateKey, TestSigningKey;
    }
}
