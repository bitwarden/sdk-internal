//! Trust proofs: how the caller knows that a key belongs to the intended recipient.
//!
//! Org Membership V1 encapsulates a shared key to the recipient's public encryption key, so whoever
//! holds the matching private key gets the shared key. A public key that the server supplies can be
//! swapped by the server, so the caller must trust the public key before the key is shared. In V1,
//! the trust is manual, through a trusted thumbprint of the public key. In some cases the trust is
//! cryptographic, because the caller holds the matching private key.
//!
//! Org Membership V2 seals keys between identities. The sender and the recipient each hold a
//! signing key, so each side can verify the identity of the other without a manually trusted
//! thumbprint.

use bitwarden_crypto::{
    CoseKeyThumbprint, CoseKeyThumbprintExt, KeySlotIds, KeyStoreContext, PublicKey,
};

/// The proof that the caller trusts the recipient's public key.
pub enum TrustProof<Ids: KeySlotIds> {
    /// The thumbprint of a public key that a person verified, or that reached the caller over a
    /// channel the server does not control, such as an invite link.
    ManuallyTrusted(CoseKeyThumbprint),
    /// A cryptographic proof that the public key belongs to the recipient.
    CryptographicallyTrusted(CryptographicProof<Ids>),
    /// Verifies with a fixed result, so that the tests of callers do not repeat the key setup of
    /// each proof.
    #[cfg(test)]
    #[expect(private_interfaces)]
    TestStub(Result<(), TrustProofError>),
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
    ThumbprintMismatch,
    MissingOwnPrivateKey,
    OwnPublicKeyMismatch,
}

impl<Ids: KeySlotIds> TrustProof<Ids> {
    /// Verifies that `public_key` satisfies the proof.
    ///
    /// A public key without a thumbprint cannot match a trusted thumbprint, so it is a mismatch.
    pub(crate) fn verify(
        &self,
        public_key: &PublicKey,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<(), TrustProofError> {
        match self {
            Self::ManuallyTrusted(trusted_thumbprint) => match public_key.thumbprint() {
                Ok(thumbprint) if &thumbprint == trusted_thumbprint => Ok(()),
                _ => Err(TrustProofError::ThumbprintMismatch),
            },
            Self::CryptographicallyTrusted(CryptographicProof::OwnPrivateKey(private_key)) => {
                let own_public_key = ctx
                    .get_public_key(*private_key)
                    .map_err(|_| TrustProofError::MissingOwnPrivateKey)?;
                if &own_public_key != public_key {
                    return Err(TrustProofError::OwnPublicKeyMismatch);
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
    use crate::test_support::TestIds;

    #[test]
    fn test_manually_trusted_thumbprint_of_the_public_key_verifies() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let public_key = ctx.get_public_key(private_key).unwrap();
        let trust_proof = TrustProof::ManuallyTrusted(public_key.thumbprint().unwrap());

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
        let trust_proof = TrustProof::ManuallyTrusted(other_public_key.thumbprint().unwrap());

        let result = trust_proof.verify(&ctx.get_public_key(private_key).unwrap(), &ctx);

        assert!(matches!(result, Err(TrustProofError::ThumbprintMismatch)));
    }

    #[test]
    fn test_own_private_key_of_the_public_key_verifies() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let trust_proof =
            TrustProof::CryptographicallyTrusted(CryptographicProof::OwnPrivateKey(private_key));

        let result = trust_proof.verify(&ctx.get_public_key(private_key).unwrap(), &ctx);

        assert!(matches!(result, Ok(())));
    }

    #[test]
    fn test_own_private_key_missing_from_the_context_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let public_key = ctx.get_public_key(private_key).unwrap();
        let trust_proof =
            TrustProof::CryptographicallyTrusted(CryptographicProof::OwnPrivateKey(private_key));
        let other_key_store = KeyStore::<TestIds>::default();
        let other_ctx = other_key_store.context();

        let result = trust_proof.verify(&public_key, &other_ctx);

        assert!(matches!(result, Err(TrustProofError::MissingOwnPrivateKey)));
    }

    #[test]
    fn test_own_private_key_of_another_key_pair_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let other_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let trust_proof = TrustProof::CryptographicallyTrusted(CryptographicProof::OwnPrivateKey(
            other_private_key,
        ));

        let result = trust_proof.verify(&ctx.get_public_key(private_key).unwrap(), &ctx);

        assert!(matches!(result, Err(TrustProofError::OwnPublicKeyMismatch)));
    }
}
