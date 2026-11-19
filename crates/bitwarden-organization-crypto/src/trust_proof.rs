//! Trust proofs: how the caller knows that a key belongs to the intended recipient.
//!
//! Org Membership V1 encapsulates a shared key to the recipient's public encryption key, so whoever
//! holds the matching private key gets the shared key. A public key that the server supplies can be
//! swapped by the server, so the caller must trust the public key before the key is shared. In V1,
//! the trust is manual: a person compared the fingerprint phrase of the public key, or the caller
//! has the thumbprint of the public key from a trusted source. In some cases the trust is
//! cryptographic, because the caller holds the matching private key.
//!
//! Org Membership V2 seals keys between identities, which authenticates the sender. An identity
//! that the caller has not trusted before still needs a manual check, such as a comparison of the
//! fingerprint phrase.

use bitwarden_crypto::{
    CoseKeyThumbprint, CoseKeyThumbprintExt, KeySlotIds, KeyStoreContext, PublicKey, fingerprint,
};
use uuid::Uuid;

/// The proof that the caller trusts the recipient's public key.
pub enum TrustProof<Ids: KeySlotIds> {
    /// The fingerprint phrase that a person compared.
    ManuallyTrustedFingerprint(FingerprintPhrase),
    /// The thumbprint of a public key from a trusted source.
    ManuallyTrustedThumbprint(CoseKeyThumbprint),
    /// A cryptographic proof that the public key belongs to the recipient.
    CryptographicallyTrusted(CryptographicProof<Ids>),
    /// Verifies with a fixed result, so that the tests of callers do not repeat the key setup of
    /// each proof.
    #[cfg(test)]
    #[expect(private_interfaces)]
    TestStub(Result<(), TrustProofError>),
}

/// The fingerprint phrase of a public key, as shown to a person.
pub struct FingerprintPhrase {
    /// The id of the key owner: the user id of a member, or the id of an organization.
    pub fingerprint_material: Uuid,
    /// The words of the fingerprint, joined with `-`.
    pub phrase: String,
}

/// The kinds of cryptographic proof.
pub enum CryptographicProof<Ids: KeySlotIds> {
    /// The caller holds the matching private key in the key store context, for example the
    /// user's own key pair, or the organization's key pair held by an admin.
    OwnPrivateKey(Ids::Private),
}

/// The ways a public key can fail its trust proof.
#[derive(Clone, Copy)]
pub(crate) enum TrustProofError {
    /// The private key of [`CryptographicProof::OwnPrivateKey`] is not in the key store context.
    PrivateKeyNotInContext,
    /// The public key does not match the trusted fingerprint phrase or thumbprint, or does not
    /// belong to the key pair of the proof.
    UntrustedPublicKey,
}

impl<Ids: KeySlotIds> TrustProof<Ids> {
    /// Verifies that `public_key` satisfies the proof.
    ///
    /// A public key without a fingerprint phrase or a thumbprint cannot match a trusted one, so it
    /// is untrusted.
    pub(crate) fn verify(
        &self,
        public_key: &PublicKey,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<(), TrustProofError> {
        match self {
            Self::ManuallyTrustedFingerprint(trusted_fingerprint) => {
                let phrase = public_key.to_der().and_then(|spki| {
                    fingerprint(&trusted_fingerprint.fingerprint_material.to_string(), &spki)
                });
                match phrase {
                    Ok(phrase) if phrase == trusted_fingerprint.phrase => Ok(()),
                    _ => Err(TrustProofError::UntrustedPublicKey),
                }
            }
            Self::ManuallyTrustedThumbprint(trusted_thumbprint) => match public_key.thumbprint() {
                Ok(thumbprint) if &thumbprint == trusted_thumbprint => Ok(()),
                _ => Err(TrustProofError::UntrustedPublicKey),
            },
            Self::CryptographicallyTrusted(CryptographicProof::OwnPrivateKey(private_key)) => {
                let own_public_key = ctx
                    .get_public_key(*private_key)
                    .map_err(|_| TrustProofError::PrivateKeyNotInContext)?;
                if &own_public_key != public_key {
                    return Err(TrustProofError::UntrustedPublicKey);
                }
                Ok(())
            }
            #[cfg(test)]
            Self::TestStub(result) => *result,
        }
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{KeyStore, PublicKeyEncryptionAlgorithm};

    use super::*;
    use crate::test_support::{TestIds, unwrap_v1_organization_private_key};

    /// The id of the organization whose key pair is in the shared V1 test vectors.
    const TEST_VECTOR_V1_ORGANIZATION_ID: &str = "0790758b-61d1-4a4d-9839-bf6e51bdf1f0";
    /// The fingerprint phrase of the V1 organization public key, derived with
    /// [`TEST_VECTOR_V1_ORGANIZATION_ID`].
    const TEST_VECTOR_V1_ORGANIZATION_FINGERPRINT_PHRASE: &str =
        "overlaid-reference-concierge-sharper-scorpion";

    fn test_vector_v1_organization_fingerprint_phrase() -> FingerprintPhrase {
        FingerprintPhrase {
            fingerprint_material: TEST_VECTOR_V1_ORGANIZATION_ID.parse().unwrap(),
            phrase: TEST_VECTOR_V1_ORGANIZATION_FINGERPRINT_PHRASE.to_string(),
        }
    }

    #[test]
    #[ignore = "Manual test to generate test vectors"]
    fn generate_test_vectors() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let public_key = unwrap_v1_organization_private_key(&mut ctx)
            .public_key(&ctx)
            .unwrap();

        println!(
            "const TEST_VECTOR_V1_ORGANIZATION_FINGERPRINT_PHRASE: &str = \"{}\";",
            fingerprint(
                TEST_VECTOR_V1_ORGANIZATION_ID,
                &public_key.to_der().unwrap()
            )
            .unwrap()
        );
    }

    #[test]
    fn test_manually_trusted_fingerprint_of_the_public_key_verifies() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let public_key = unwrap_v1_organization_private_key(&mut ctx)
            .public_key(&ctx)
            .unwrap();
        let trust_proof = TrustProof::ManuallyTrustedFingerprint(
            test_vector_v1_organization_fingerprint_phrase(),
        );

        let result = trust_proof.verify(&public_key, &ctx);

        assert!(matches!(result, Ok(())));
    }

    #[test]
    fn test_manually_trusted_fingerprint_of_another_public_key_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let other_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let trust_proof = TrustProof::ManuallyTrustedFingerprint(
            test_vector_v1_organization_fingerprint_phrase(),
        );

        let result = trust_proof.verify(&ctx.get_public_key(other_private_key).unwrap(), &ctx);

        assert!(matches!(result, Err(TrustProofError::UntrustedPublicKey)));
    }

    #[test]
    fn test_manually_trusted_fingerprint_of_other_fingerprint_material_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let public_key = unwrap_v1_organization_private_key(&mut ctx)
            .public_key(&ctx)
            .unwrap();
        let trust_proof = TrustProof::ManuallyTrustedFingerprint(FingerprintPhrase {
            fingerprint_material: Uuid::new_v4(),
            phrase: TEST_VECTOR_V1_ORGANIZATION_FINGERPRINT_PHRASE.to_string(),
        });

        let result = trust_proof.verify(&public_key, &ctx);

        assert!(matches!(result, Err(TrustProofError::UntrustedPublicKey)));
    }

    #[test]
    fn test_manually_trusted_thumbprint_of_the_public_key_verifies() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let public_key = ctx.get_public_key(private_key).unwrap();
        let trust_proof = TrustProof::ManuallyTrustedThumbprint(public_key.thumbprint().unwrap());

        let result = trust_proof.verify(&public_key, &ctx);

        assert!(matches!(result, Ok(())));
    }

    #[test]
    fn test_manually_trusted_thumbprint_of_another_public_key_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let other_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let other_public_key = ctx.get_public_key(other_private_key).unwrap();
        let trust_proof =
            TrustProof::ManuallyTrustedThumbprint(other_public_key.thumbprint().unwrap());

        let result = trust_proof.verify(&ctx.get_public_key(private_key).unwrap(), &ctx);

        assert!(matches!(result, Err(TrustProofError::UntrustedPublicKey)));
    }

    #[test]
    fn test_cryptographically_trusted_own_private_key_of_the_public_key_verifies() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let trust_proof =
            TrustProof::CryptographicallyTrusted(CryptographicProof::OwnPrivateKey(private_key));

        let result = trust_proof.verify(&ctx.get_public_key(private_key).unwrap(), &ctx);

        assert!(matches!(result, Ok(())));
    }

    #[test]
    fn test_cryptographically_trusted_own_private_key_missing_from_the_context_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let public_key = ctx.get_public_key(private_key).unwrap();
        let trust_proof =
            TrustProof::CryptographicallyTrusted(CryptographicProof::OwnPrivateKey(private_key));
        let other_key_store = KeyStore::<TestIds>::default();
        let other_ctx = other_key_store.context();

        let result = trust_proof.verify(&public_key, &other_ctx);

        assert!(matches!(
            result,
            Err(TrustProofError::PrivateKeyNotInContext)
        ));
    }

    #[test]
    fn test_cryptographically_trusted_own_private_key_of_another_key_pair_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let other_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let trust_proof = TrustProof::CryptographicallyTrusted(CryptographicProof::OwnPrivateKey(
            other_private_key,
        ));

        let result = trust_proof.verify(&ctx.get_public_key(private_key).unwrap(), &ctx);

        assert!(matches!(result, Err(TrustProofError::UntrustedPublicKey)));
    }
}
