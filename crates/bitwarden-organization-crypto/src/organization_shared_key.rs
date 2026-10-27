//! Organization shared key: the organization key shared with one member, so that the member can
//! decrypt the organization's data.
//!
//! The API names this value the membership's `key`.
//!
//! # Versions
//!
//! - V1: the organization key encapsulated to the member's public key. Nothing authenticates the
//!   sender, so the member cannot tell that the organization made it.
//! - V2 (planned): the organization key sealed from the organization's identity to the member's
//!   identity in an identity-sealed key envelope, which authenticates the organization as the
//!   sender.
//!
//! [`OrganizationSharedKey::make`] takes the [`TrustProof`] for the member's public key: the
//! fingerprint check of an admin, or the member's own private key when the member shares the key
//! with themselves (creating an organization, or self-confirming through an invite link). Some V1
//! flows have no way to verify the public key, and use [`OrganizationSharedKey::make_untrusted`].
//! V2 has no untrusted variant.

use std::str::FromStr;

use bitwarden_crypto::{KeySlotIds, KeyStoreContext, PublicKey, UnsignedSharedKey};
use thiserror::Error;

use crate::trust_proof::{TrustProof, TrustProofError};

/// Errors that can occur when parsing an organization shared key.
#[derive(Debug, Error)]
pub enum OrganizationSharedKeyParseError {
    /// The value stored for the membership is in no known organization shared key format.
    #[error("The organization shared key is malformed")]
    Malformed,
}

/// Errors that can occur when making an organization shared key with a trust proof.
#[derive(Debug, Error)]
pub enum OrganizationSharedKeyMakeError {
    /// The server supplied a public key other than the trusted one.
    #[error("The member's public key does not match the trusted thumbprint")]
    ThumbprintMismatch,
    /// The private key of the proof is not in the key store context.
    #[error("The own private key does not exist in the key store context")]
    MissingOwnPrivateKey,
    /// The public key does not belong to the key pair of the proof.
    #[error("The member's public key does not match the own private key")]
    OwnPublicKeyMismatch,
    /// The organization key is not in the key store context.
    #[error("The organization key could not be encapsulated to the member's public key")]
    EncapsulationFailed,
}

impl From<TrustProofError> for OrganizationSharedKeyMakeError {
    fn from(error: TrustProofError) -> Self {
        match error {
            TrustProofError::ThumbprintMismatch => Self::ThumbprintMismatch,
            TrustProofError::MissingOwnPrivateKey => Self::MissingOwnPrivateKey,
            TrustProofError::OwnPublicKeyMismatch => Self::OwnPublicKeyMismatch,
        }
    }
}

/// Errors that can occur when making an organization shared key without a trust proof.
#[derive(Debug, Error)]
pub enum OrganizationSharedKeyMakeUntrustedError {
    /// The organization key is not in the key store context.
    #[error("The organization key could not be encapsulated to the member's public key")]
    EncapsulationFailed,
}

/// Errors that can occur when unsealing an organization shared key.
#[derive(Debug, Error)]
pub enum OrganizationSharedKeyUnsealError {
    /// The organization shared key was made for a different key pair, or the stored value is
    /// corrupt. V1 cannot tell these apart.
    #[error("The organization shared key could not be decapsulated with the own private key")]
    DecapsulationFailed,
}

/// The organization key, shared with one member.
pub enum OrganizationSharedKey {
    /// The organization key encapsulated to the member's public key.
    ///
    /// Encapsulation authenticates no sender. Anyone who knows the member's public key can make
    /// one, and a swapped public key hands the organization key to whoever holds the matching
    /// private key.
    V1(UnsignedSharedKey),
}

impl OrganizationSharedKey {
    /// Makes an organization shared key for a member, after the member's public key passes
    /// `trust_proof`.
    pub fn make<Ids: KeySlotIds>(
        organization_key: Ids::Symmetric,
        member_public_key: &PublicKey,
        trust_proof: &TrustProof<Ids>,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, OrganizationSharedKeyMakeError> {
        trust_proof.verify(member_public_key, ctx)?;

        let encapsulated_key =
            UnsignedSharedKey::encapsulate(organization_key, member_public_key, ctx)
                .map_err(|_| OrganizationSharedKeyMakeError::EncapsulationFailed)?;

        Ok(Self::V1(encapsulated_key))
    }

    /// Makes a V1 organization shared key for a member, without verifying the member's public
    /// key.
    ///
    /// Only for V1 flows that have no way to verify the public key. A swapped public key hands the
    /// organization key to whoever holds the matching private key.
    pub fn make_untrusted<Ids: KeySlotIds>(
        organization_key: Ids::Symmetric,
        member_public_key: &PublicKey,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, OrganizationSharedKeyMakeUntrustedError> {
        let encapsulated_key =
            UnsignedSharedKey::encapsulate(organization_key, member_public_key, ctx)
                .map_err(|_| OrganizationSharedKeyMakeUntrustedError::EncapsulationFailed)?;

        Ok(Self::V1(encapsulated_key))
    }

    /// Opens the organization key with the member's own private key, returning the id it was added
    /// to the context under.
    pub fn unseal<Ids: KeySlotIds>(
        &self,
        own_private_key: Ids::Private,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, OrganizationSharedKeyUnsealError> {
        let Self::V1(encapsulated_key) = self;

        encapsulated_key
            .decapsulate(own_private_key, ctx)
            .map_err(|_| OrganizationSharedKeyUnsealError::DecapsulationFailed)
    }
}

impl FromStr for OrganizationSharedKey {
    type Err = OrganizationSharedKeyParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .parse()
            .map(Self::V1)
            .map_err(|_| OrganizationSharedKeyParseError::Malformed)
    }
}

impl From<&OrganizationSharedKey> for String {
    fn from(value: &OrganizationSharedKey) -> Self {
        let OrganizationSharedKey::V1(encapsulated_key) = value;

        encapsulated_key.to_string()
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{
        CoseKeyThumbprintExt, EncString, KeyStore, PublicKeyEncryptionAlgorithm,
        SymmetricCryptoKey, SymmetricKeyAlgorithm::Aes256CbcHmac,
    };

    use super::*;
    use crate::{
        test_support::{
            TEST_VECTOR_V1_MEMBER_USER_KEY, TEST_VECTOR_V1_ORG_KEY, TestIds, TestPrivateKey,
            add_symmetric_key,
        },
        trust_proof::CryptographicProof,
    };

    /// The member private key, wrapped with [`TEST_VECTOR_V1_MEMBER_USER_KEY`].
    const TEST_VECTOR_MEMBER_WRAPPED_PRIVATE_KEY: &str = "2.Fk2Qw03uGzzqZ64D3yKYEw==|VFfJlJ9/bMF9usPNP1Czzpc57hS/mVublKvpUsgxbWohkunlBxz1lVwOknAxtVprt9a4W9rKFjT+xDY1ImpQijt+MgGRAsXqURlGWY2W7CUs7tN9f5M598R5SXopVXhIYv8uVvMPv7zMEa6sl2p0XvMNkjn/02h2UHm1R9Wpnvb8MeGkXVBwGVfP53FaBR8iHsDQu7pR6MP8nYqRUg9+ORbqId453BpUycJt6TD59JEEUOG90T57UQRWIBOPmjtN8eF/EaVMK9fzYwCbKqa187x7B7BCuqKXSzjfFdSt+xNLmZMPRRB1DZB9NvabsQF87175wsnHOFqrcTXhAORvVpse1EpVSWR+u8K3p9chqjzlGCthb72OEET1hV1MSYWv1osDnqhNl981zz9oDToRk3ZEhktZyA7Uox9g2Abuf3xVpkCCO/bb3rcpTmmhk5BP3npfluUyEbpCRNcyi1kYpAF6vtY+UYaAv4XB25Dcp5td/c2yrlIUJeM17GFCm/TQGU7kMo7S3CFcM9nmFFG60aM8eQiwF1HQZV9cMPLNiNFwDFdmUcv+m/eZ/4ZZM8WJv4raevjoFUPgb8saqOSLKYGisjGoyJ7Z9T1eZisyALEfgIVbsJrINWjjW1pVxDNMiatn8ZDA4S90rUYl2eejNie+2e+41KAYl3JSZlkqr636A2gkLzToufXpX+n655hz9yNMhv5TnfenzTaMDg1XCETqiixKQBxV8m4VsJbGBIzNVzghoJUuf8xZ90FmhWeH6z8It6f/uVwlnBLG1m690AWJXVtMmEejrwJAcmJKYntFHtZI54SUJfXyW33vaQ7tQbQ699BqU9nGQcTnDbTmdA2iyDLuJ2n06B8PYK4odSfCQJrOWHsdZpRd7P1lDp7ksxejqafJJfXsD0BvoUbw8CGe5eGotGlyv85poSduLeURqyai6y4eW0UClXJJiaUXMlXNbzrTCSeWb6aWJTxQfW/fQ0QNjIqDOB5B4xByh/mzESOiyTEnNV61Ln2HOGlpfkhARLpgGdotYvZtFQRrApqvWwRtIerP2gZfpubAN29J5lW2DHAkd6fvEFokjQ4wofqymwNxVVd5WBjueQ1RbFdo1LMIiKApEMTpQ5E4eipmtDc6foFJo26FIuXvHduKOBZm0rYfd8Iw5EgQMXyKaUE1KxU9HHdR4BFzT9JEacNPkdF96DSbV/l6lVADDc0xfRe7AAXAmPxRlHDMw4HGlTbOXlhNZQtkX7mUMyVheRudwsmOvH/BvbJajn1E+xYy4r1GdTbvJRvzAjhK1Xdniq4bAD1brVPdnkk7yhTEHT1GnGEMn3kPtBhuBIKhNSwYZdG88NcwDzwDhrssU77jSIB72RjtOpO4nlMnqmjGpwFakJmLgaonYgIArIBqaJQ7Kt/JfIUGiARkO6IVF3WF8cL5/GUI7KpyZATbBIX4bfuJXBlmEPBneKduLCt+svBW1XVctOwArsYfypCsQojmMRNQkHC8EgCumQxc8Wutl7jXh8OwIXDHZjQ6UJw8XK2vmuS6oBRQg9SwzeQlIbsz1sQRpuAx/IY7TwTZOOi0bp5KdnZzSCx6SbUP7ZDdbGQb4ZH3GCXkOgvK0MsH5GEUjnEa8afSJGh/hEulDEsFE5g=|HA79iaX6imq4ipukZLyw6Nd1PhIT7/pCInWPmgr4YKA=";
    /// [`TEST_VECTOR_V1_ORG_KEY`] encapsulated to the pinned member public key.
    const TEST_VECTOR_ORGANIZATION_SHARED_KEY: &str = "4.HtHhO4krfvZnoJRJFkXpf9BLLyrOO0ovfxTsmt0GNKkT7clpMVNR0W7B8VOEiautOVW6zAMDVzO2ZlFhrVR6kt5ATXL1KCqjipHBI2u/6Ww3Dh2jlUZuRTFcbZ4bYN3sOVQPkdwFaM1H++SzauUWP7pmzSc+u4sQIUKAB/KJ5OSkKn3tFYZuwUycB+wgcA4Ew8qU3c46lCbKqXY8dI3Z1ttvC5vO81cM4pryNGoHnaI7ONeEIuGIA5py8/WP58R6mQhyQWwC2uq77caFRX8GLGJd3c3yYfH1em5NvF8BZzZ1TZ/Nd+6fS4T8awUjs4IxkxJw6eU6Wn8+y4tUM9gAxw==";

    /// Unwraps the member private key with the member user key.
    fn load_member_private_key(ctx: &mut KeyStoreContext<'_, TestIds>) -> TestPrivateKey {
        let member_user_key = add_symmetric_key(TEST_VECTOR_V1_MEMBER_USER_KEY, ctx);
        let wrapped_private_key: EncString =
            TEST_VECTOR_MEMBER_WRAPPED_PRIVATE_KEY.parse().unwrap();
        ctx.unwrap_private_key(member_user_key, &wrapped_private_key)
            .unwrap()
    }

    fn own_private_key_proof(private_key: TestPrivateKey) -> TrustProof<TestIds> {
        TrustProof::CryptographicallyTrusted(CryptographicProof::OwnPrivateKey(private_key))
    }

    #[test]
    fn test_organization_shared_key_with_the_trusted_thumbprint_unseals_to_the_organization_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_key = ctx.make_symmetric_key(Aes256CbcHmac);
        let member_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let member_public_key = ctx.get_public_key(member_private_key).unwrap();

        let shared_key = OrganizationSharedKey::make(
            organization_key,
            &member_public_key,
            &TrustProof::ManuallyTrusted(member_public_key.thumbprint().unwrap()),
            &ctx,
        )
        .unwrap();
        let unsealed = shared_key.unseal(member_private_key, &mut ctx).unwrap();

        ctx.assert_symmetric_keys_equal(organization_key, unsealed);
    }

    #[test]
    fn test_organization_shared_key_for_own_private_key_unseals_to_the_organization_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_key = ctx.make_symmetric_key(Aes256CbcHmac);
        let own_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let own_public_key = ctx.get_public_key(own_private_key).unwrap();

        let shared_key = OrganizationSharedKey::make(
            organization_key,
            &own_public_key,
            &own_private_key_proof(own_private_key),
            &ctx,
        )
        .unwrap();
        let unsealed = shared_key.unseal(own_private_key, &mut ctx).unwrap();

        ctx.assert_symmetric_keys_equal(organization_key, unsealed);
    }

    #[test]
    fn test_untrusted_organization_shared_key_unseals_to_the_organization_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_key = ctx.make_symmetric_key(Aes256CbcHmac);
        let member_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let member_public_key = ctx.get_public_key(member_private_key).unwrap();

        let shared_key =
            OrganizationSharedKey::make_untrusted(organization_key, &member_public_key, &ctx)
                .unwrap();
        let unsealed = shared_key.unseal(member_private_key, &mut ctx).unwrap();

        ctx.assert_symmetric_keys_equal(organization_key, unsealed);
    }

    #[test]
    fn test_organization_shared_key_survives_a_string_round_trip() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_key = ctx.make_symmetric_key(Aes256CbcHmac);
        let own_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let own_public_key = ctx.get_public_key(own_private_key).unwrap();
        let shared_key = OrganizationSharedKey::make(
            organization_key,
            &own_public_key,
            &own_private_key_proof(own_private_key),
            &ctx,
        )
        .unwrap();

        let parsed: OrganizationSharedKey = String::from(&shared_key).parse().unwrap();

        let unsealed = parsed.unseal(own_private_key, &mut ctx).unwrap();
        ctx.assert_symmetric_keys_equal(organization_key, unsealed);
    }

    #[test]
    fn test_parsing_a_key_in_no_known_format_fails() {
        let result: Result<OrganizationSharedKey, _> = "not an encapsulated key".parse();

        assert!(matches!(
            result,
            Err(OrganizationSharedKeyParseError::Malformed)
        ));
    }

    #[test]
    fn test_making_for_a_public_key_with_another_thumbprint_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_key = ctx.make_symmetric_key(Aes256CbcHmac);
        let member_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let trusted_thumbprint = ctx
            .get_public_key(member_private_key)
            .unwrap()
            .thumbprint()
            .unwrap();
        let other_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let other_public_key = ctx.get_public_key(other_private_key).unwrap();

        let result = OrganizationSharedKey::make(
            organization_key,
            &other_public_key,
            &TrustProof::ManuallyTrusted(trusted_thumbprint),
            &ctx,
        );

        assert!(matches!(
            result,
            Err(OrganizationSharedKeyMakeError::ThumbprintMismatch)
        ));
    }

    #[test]
    fn test_making_with_a_missing_own_private_key_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_key = ctx.make_symmetric_key(Aes256CbcHmac);
        let other_key_store = KeyStore::<TestIds>::default();
        let mut other_ctx = other_key_store.context_mut();
        let missing_private_key =
            other_ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let missing_public_key = other_ctx.get_public_key(missing_private_key).unwrap();

        let result = OrganizationSharedKey::make(
            organization_key,
            &missing_public_key,
            &own_private_key_proof(missing_private_key),
            &ctx,
        );

        assert!(matches!(
            result,
            Err(OrganizationSharedKeyMakeError::MissingOwnPrivateKey)
        ));
    }

    #[test]
    fn test_making_for_a_public_key_of_another_key_pair_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_key = ctx.make_symmetric_key(Aes256CbcHmac);
        let own_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let other_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let other_public_key = ctx.get_public_key(other_private_key).unwrap();

        let result = OrganizationSharedKey::make(
            organization_key,
            &other_public_key,
            &own_private_key_proof(own_private_key),
            &ctx,
        );

        assert!(matches!(
            result,
            Err(OrganizationSharedKeyMakeError::OwnPublicKeyMismatch)
        ));
    }

    #[test]
    fn test_making_with_a_missing_organization_key_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let own_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let own_public_key = ctx.get_public_key(own_private_key).unwrap();
        let other_key_store = KeyStore::<TestIds>::default();
        let mut other_ctx = other_key_store.context_mut();
        let missing_organization_key = other_ctx.make_symmetric_key(Aes256CbcHmac);

        let result = OrganizationSharedKey::make(
            missing_organization_key,
            &own_public_key,
            &own_private_key_proof(own_private_key),
            &ctx,
        );

        assert!(matches!(
            result,
            Err(OrganizationSharedKeyMakeError::EncapsulationFailed)
        ));
    }

    #[test]
    fn test_making_untrusted_with_a_missing_organization_key_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let member_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let member_public_key = ctx.get_public_key(member_private_key).unwrap();
        let other_key_store = KeyStore::<TestIds>::default();
        let mut other_ctx = other_key_store.context_mut();
        let missing_organization_key = other_ctx.make_symmetric_key(Aes256CbcHmac);

        let result = OrganizationSharedKey::make_untrusted(
            missing_organization_key,
            &member_public_key,
            &ctx,
        );

        assert!(matches!(
            result,
            Err(OrganizationSharedKeyMakeUntrustedError::EncapsulationFailed)
        ));
    }

    #[test]
    fn test_unsealing_with_another_private_key_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_key = ctx.make_symmetric_key(Aes256CbcHmac);
        let member_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let member_public_key = ctx.get_public_key(member_private_key).unwrap();
        let other_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let shared_key =
            OrganizationSharedKey::make_untrusted(organization_key, &member_public_key, &ctx)
                .unwrap();

        let result = shared_key.unseal(other_private_key, &mut ctx);

        assert!(matches!(
            result,
            Err(OrganizationSharedKeyUnsealError::DecapsulationFailed)
        ));
    }

    #[test]
    #[ignore = "Manual test to generate test vectors"]
    fn generate_test_vectors() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let member_user_key = SymmetricCryptoKey::make(Aes256CbcHmac);
        let member_user_key_b64 = member_user_key.to_base64();
        let member_user_key = ctx.add_local_symmetric_key(member_user_key);
        let member_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let wrapped_member_private_key = ctx
            .wrap_private_key(member_user_key, member_private_key)
            .unwrap();
        let member_public_key = ctx.get_public_key(member_private_key).unwrap();
        let organization_key = add_symmetric_key(TEST_VECTOR_V1_ORG_KEY, &mut ctx);

        let shared_key =
            OrganizationSharedKey::make_untrusted(organization_key, &member_public_key, &ctx)
                .unwrap();

        println!("const TEST_VECTOR_V1_MEMBER_USER_KEY: &str = \"{member_user_key_b64}\";");
        println!(
            "const TEST_VECTOR_MEMBER_WRAPPED_PRIVATE_KEY: &str = \"{}\";",
            wrapped_member_private_key.to_string()
        );
        println!(
            "const TEST_VECTOR_ORGANIZATION_SHARED_KEY: &str = \"{}\";",
            String::from(&shared_key)
        );
    }

    #[test]
    fn test_organization_shared_key_test_vector() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let member_private_key = load_member_private_key(&mut ctx);
        let organization_key = add_symmetric_key(TEST_VECTOR_V1_ORG_KEY, &mut ctx);

        let shared_key: OrganizationSharedKey =
            TEST_VECTOR_ORGANIZATION_SHARED_KEY.parse().unwrap();
        let unsealed = shared_key.unseal(member_private_key, &mut ctx).unwrap();

        ctx.assert_symmetric_keys_equal(organization_key, unsealed);
    }
}
