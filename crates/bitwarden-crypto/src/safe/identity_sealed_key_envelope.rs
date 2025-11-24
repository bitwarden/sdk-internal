//! Identity sealed key envelope is used to transport a key between two cryptographic identities.
//!
//! It implements signcryption of a key. The cryptographic objects strongly binds to the receiving and sending cryptographic identities.
//! The interfaces also require a cryptographic attestation, where the recipient provides a claim over the public encryption key it is
//! receiving on.

use crate::{AsymmetricCryptoKey, SignedPublicKey, SymmetricCryptoKey, VerifyingKey, cose};

pub struct IdentitySealedKeyEnvelope {
    cose_encrypt: coset::CoseSign,
}

pub enum IdentitySealedKeyEnvelopeError {
    VerificationFailed,
}

impl IdentitySealedKeyEnvelope {
    pub fn seal(
        sender_verifying_key: VerifyingKey,
        recipient_verifying_key: VerifyingKey,
        recipient_public_key: SignedPublicKey,
        key_to_share: &SymmetricCryptoKey,
    ) -> Self {
        let a = coset::CoseEncryptBuilder::new()
            .add_recipient(
                coset::HeaderBuilder::new().algorithm(coset::Algorithm::Assigned(
                    coset::AlgorithmAssigned::RsaOaep256,
                )),
            )
            .build();

        todo!();
    }

    pub fn unseal(
        &self,
        sender_verifying_key: VerifyingKey,
        recipient_verifying_key: VerifyingKey,
        recipient_private_key: AsymmetricCryptoKey,
    ) -> Result<SymmetricCryptoKey, IdentitySealedKeyEnvelopeError> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_identity_sealed_key_envelope() {}
}
