//! This example demonstrates how to sign and verify structs.

use bitwarden_crypto::{AsymmetricCryptoKey, CoseSerializable, CoseSign1Bytes, DeriveFingerprint, KeyFingerprint, PublicKeyEncryptionAlgorithm, SignedObject, SignedPublicKeyMessage, SigningNamespace, SymmetricCryptoKey, safe::IdentitySealedKeyEnvelope};

use serde::{Deserialize, Serialize};

const EXAMPLE_NAMESPACE: &SigningNamespace = &SigningNamespace::SignedPublicKey;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityClaim {
    identity_fingerprint: KeyFingerprint,
    identifier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MembershipAgreement {
    member_identity: KeyFingerprint,
    organization_identity: KeyFingerprint,
}

fn main() {
    // Setup keys for both sides
    // Alice
    let alice_signature_key =
        bitwarden_crypto::SigningKey::make(bitwarden_crypto::SignatureAlgorithm::Ed25519);
    let alice_verifying_key = alice_signature_key.to_verifying_key();
    let alice_private_key = AsymmetricCryptoKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
    let signed_public_key = SignedPublicKeyMessage::from_public_key(&alice_private_key.to_public_key()).unwrap();
    let signed_public_key = signed_public_key.sign(&alice_signature_key).unwrap();
    // Admin
    let admin_signature_key =
        bitwarden_crypto::SigningKey::make(bitwarden_crypto::SignatureAlgorithm::Ed25519);
    let admin_verifying_key = admin_signature_key.to_verifying_key(); 
    let org_symmetric_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();


    // Alice joins. This is Step 2 in the 3 step process
    let identity_claim = IdentityClaim {
        identity_fingerprint: admin_verifying_key.fingerprint(),
        identifier: "organization_name".to_string(),
    };
    alice_signature_key.sign(&identity_claim, &SigningNamespace::IdentityClaim).unwrap();
    let membership_agreement = MembershipAgreement {
        member_identity: alice_verifying_key.fingerprint(),
        organization_identity: admin_verifying_key.fingerprint(),
    };
    let (signature, serialized_message) = admin_signature_key
        .sign_detached(&membership_agreement, &SigningNamespace::MembershipAgreement)
        .unwrap();
    // upload to server: serialized_message, signature

    // Admin verifies
    assert!(signature.verify(
        &serialized_message.as_bytes(),
        &admin_verifying_key,
        &SigningNamespace::MembershipAgreement,
    ));

    let counter_signature = alice_signature_key
        .counter_sign_detached(
            serialized_message.as_bytes().to_vec(),
            &signature,
            &SigningNamespace::MembershipAgreement,
        )
        .unwrap();
    let identity_sealed_key_envelope = IdentitySealedKeyEnvelope::seal(
        &admin_signature_key,
        &alice_verifying_key,
        &signed_public_key,
        &org_symmetric_key,
    ).unwrap();
    // upload to server: identity_sealed_key_envelope, counter_signature

    // To load a key, alice will have to verify that the membership agreement was signed by admin and her.
    assert!(signature.verify(
        &serialized_message.as_bytes(),
        &admin_verifying_key,
        &SigningNamespace::MembershipAgreement,
    ));
    assert!(counter_signature.verify(
        &serialized_message.as_bytes(),
        &alice_verifying_key,
        &SigningNamespace::MembershipAgreement,
    ));
    // Then, she unseals it
    let key = identity_sealed_key_envelope
        .unseal(&admin_verifying_key, &alice_verifying_key, &alice_private_key)
        .expect("Failed to unseal organization key");
    assert_eq!(key, org_symmetric_key);
}
