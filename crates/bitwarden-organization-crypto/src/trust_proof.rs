//! Trust proofs: how the caller knows that a public key belongs to the intended recipient.
//!
//! Sharing a key to a public key hands the key to whoever holds the matching private key. A key
//! that the server supplies can be swapped by the server, so every shared key is made with a proof
//! that the caller trusts the recipient's public key.
//!
//! V1 values carry no sender authentication, so the proof protects the sender only. V2 adds
//! proofs that verify the recipient's identity, such as identity claims and signatures.

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
}

/// The kinds of cryptographic proof. V2 adds signed identity claims, which bind the public key to
/// the identity of the recipient.
pub enum CryptographicProof<Ids: KeySlotIds> {
    /// The caller holds the matching private key in the key store context, for example the
    /// user's own key pair, or the organization's key pair held by an admin.
    OwnPrivateKey(Ids::Private),
}

/// The ways a public key can fail its trust proof.
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
        }
    }
}
