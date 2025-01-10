use serde::{Deserialize, Serialize};

use crate::{
    key_hash::{self, KeyHash},
    signing,
    signing_key::{SigningCryptoKey, VerifyingCryptoKey},
    CryptoError,
};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum TrustIdentity {
    User(String),
    Organization(String),
}

#[derive(Serialize, Deserialize, PartialEq)]
struct IdentityTrustMessage {
    identity: TrustIdentity,
    verifying_key_fingerprint: KeyHash,
}

pub enum SignatureContext {
    IdentityTrust(TrustIdentity),
}

pub struct Signature {
    context: SignatureContext,
    data: Vec<u8>,
    signature_data: signing::signature::Signature,
    signing_key_hash: KeyHash,
}

/// Generate a trust signature, that shows that the current user trusts the identity of the peer
/// with the given identity key.
/// # Arguments
/// * `own_signing_key` - The signing key of the current user
/// * `peer_verifying_key` - The verifying key of the peer
/// * `peer_identity` - The identity of the peer
pub fn trust_identity_key(
    own_signing_key: &mut SigningCryptoKey,
    peer_verifying_key: &VerifyingCryptoKey,
    peer_identity: TrustIdentity,
) -> Result<Signature, CryptoError> {
    let message = IdentityTrustMessage {
        identity: peer_identity.clone(),
        verifying_key_fingerprint: key_hash::KeyHash::default(),
    };

    let message_bytes = serde_json::to_vec(&message).map_err(|_| CryptoError::InvalidKey)?;

    Ok(Signature {
        context: SignatureContext::IdentityTrust(peer_identity),
        data: message_bytes.clone(),
        signature_data: own_signing_key.signing_key.sign(&message_bytes),
        signing_key_hash: key_hash::KeyHash::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{signing::Signer, signing_key::Verifiable};

    #[test]
    fn test_trust_identity_key() {
        let mut own_signing_key = SigningCryptoKey::generate(&mut rand::thread_rng());
        let peer_signing_key = SigningCryptoKey::generate(&mut rand::thread_rng());
        let peer_verifying_key = peer_signing_key.verifier();
        let peer_identity = TrustIdentity::User("test_user_id".to_string());

        let signature =
            trust_identity_key(&mut own_signing_key, &peer_verifying_key, peer_identity)
                .expect("Failed to generate trust signature");
    }
}
