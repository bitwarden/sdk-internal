//! Implements the V2 organization protocol, that enhances cryptographic guarantees with respect to
//! a compromised server. Over the V1 protocol, this decomposes the cryptography to establish trust
//! once and only once, to be able to use this trust for other objects such as policies, and to
//! implement a new key transport mechanism that allows key rotation, and also provides sender
//! authentication.

use bitwarden_crypto::{
    AsymmetricCryptoKey, DeriveFingerprint, PublicKeyEncryptionAlgorithm, SerializedMessage,
    Signature, SignatureAlgorithm, SignedObject, SignedPublicKey, SignedPublicKeyMessage,
    SigningKey, SigningNamespace, SymmetricCryptoKey, VerifyingKey,
    safe::IdentitySealedKeyEnvelope,
};
use serde::{Deserialize, Serialize};

/// Represents a user's cryptographic identity
struct UserIdentity {
    name: String,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    private_key: AsymmetricCryptoKey,
    signed_public_key: SignedPublicKey,
}

/// Represents an organization's cryptographic identity and key material
struct OrganizationIdentity {
    name: String,
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    symmetric_key: SymmetricCryptoKey,
}

/// A claim that an identity belongs to a specific identifier (e.g., email, organization name)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityClaim {
    identity_fingerprint: bitwarden_crypto::KeyFingerprint,
    identifier: String,
}

/// An agreement between a member and an organization, signed by both parties
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MembershipAgreement {
    member_identity: bitwarden_crypto::KeyFingerprint,
    organization_identity: bitwarden_crypto::KeyFingerprint,
}

fn setup_user() -> UserIdentity {
    let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
    let verifying_key = signing_key.to_verifying_key();
    let private_key = AsymmetricCryptoKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
    let signed_public_key = SignedPublicKeyMessage::from_public_key(&private_key.to_public_key())
        .expect("Failed to create signed public key message")
        .sign(&signing_key)
        .expect("Failed to sign public key");

    UserIdentity {
        name: "Alice".to_string(),
        signing_key,
        verifying_key,
        private_key,
        signed_public_key,
    }
}

fn setup_organization() -> OrganizationIdentity {
    let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
    let verifying_key = signing_key.to_verifying_key();
    let symmetric_key = SymmetricCryptoKey::make_xchacha20_poly1305_key();

    OrganizationIdentity {
        name: "My Org Name".to_string(),
        signing_key,
        verifying_key,
        symmetric_key,
    }
}

// placeholder for out-of-band fingerprint verification
fn prompt_user_to_verify_fingerprint(_org: &OrganizationIdentity) -> bool {
    return true;
}

// placeholder for out-of-band fingerprint verification
fn prompt_organization_to_verify_fingerprint(_member: &UserIdentity) -> bool {
    return true;
}

/// Step 2: User accepts the invite by signing an identity claim and receiving a membership
/// agreement NOTE: REQUIRES OUT-OF-BAND VERIFICATION OF THE ORGANIZATION'S IDENTITY FINGERPRINT
fn user_accepts_invite(
    org: &OrganizationIdentity,
    member: &UserIdentity,
) -> (Signature, SerializedMessage, SignedObject) {
    let identity_claim = IdentityClaim {
        identity_fingerprint: org.verifying_key.fingerprint(),
        identifier: org.name.to_string(),
    };

    // Admin signs the identity claim to assert ownership
    let signed_claim = member
        .signing_key
        .sign(&identity_claim, &SigningNamespace::IdentityClaim)
        .expect("Failed to sign identity claim");

    let membership_agreement = MembershipAgreement {
        member_identity: member.verifying_key.fingerprint(),
        organization_identity: org.verifying_key.fingerprint(),
    };

    let (signature, serialized_message) = member
        .signing_key
        .sign_detached(
            &membership_agreement,
            &SigningNamespace::MembershipAgreement,
        )
        .expect("Failed to sign membership agreement");
    (signature, serialized_message, signed_claim)
}

/// Step 3: Member verifies and counter-signs the membership agreement
/// NOTE: REQUIRES ADMIN TO FIRST CONFIRM THE MEMBERS NAME TO THE FINGERPRINT OUT-OF-BAND
fn admin_confirms_join(
    member: &UserIdentity,
    org: &OrganizationIdentity,
    signature: &Signature,
    serialized_message: &SerializedMessage,
) -> (Signature, IdentitySealedKeyEnvelope, SignedObject) {
    // Verify admin's signature
    assert!(
        signature.verify(
            serialized_message.as_bytes(),
            &member.verifying_key,
            &SigningNamespace::MembershipAgreement,
        ),
        "Failed to verify admin's membership signature"
    );

    let identity_claim = IdentityClaim {
        identity_fingerprint: member.verifying_key.fingerprint(),
        identifier: member.name.to_string(),
    };
    let signed_member_claim = org
        .signing_key
        .sign(&identity_claim, &SigningNamespace::IdentityClaim)
        .expect("Failed to sign member identity claim");

    // Counter-sign to indicate acceptance
    let counter_signature = org
        .signing_key
        .counter_sign_detached(
            serialized_message.as_bytes().to_vec(),
            signature,
            &SigningNamespace::MembershipAgreement,
        )
        .expect("Failed to counter-sign membership agreement");
    let envelope = IdentitySealedKeyEnvelope::seal_ref(
        &org.signing_key,
        &member.verifying_key,
        &member.signed_public_key,
        &org.symmetric_key,
    )
    .expect("Failed to seal organization key");
    (counter_signature, envelope, signed_member_claim)
}

/// Step 5: Member loads the organization key by verifying all signatures
fn load_shared_vault_key(
    member: &UserIdentity,
    org: &OrganizationIdentity,
    admin_signature: &Signature,
    member_signature: &Signature,
    serialized_message: &SerializedMessage,
    envelope: &IdentitySealedKeyEnvelope,
) -> SymmetricCryptoKey {
    // Verify both signatures on the membership agreement
    assert!(
        admin_signature.verify(
            serialized_message.as_bytes(),
            &org.verifying_key,
            &SigningNamespace::MembershipAgreement,
        ),
        "Failed to verify admin's membership signature"
    );
    assert!(
        member_signature.verify(
            serialized_message.as_bytes(),
            &member.verifying_key,
            &SigningNamespace::MembershipAgreement,
        ),
        "Failed to verify member's membership signature"
    );

    // Unseal the organization key
    let key = envelope
        .unseal_ref(
            &org.verifying_key,
            &member.verifying_key,
            &member.private_key,
        )
        .expect("Failed to unseal organization key");
    key
}

fn main() {
    // Setup identities
    let alice = setup_user();
    let org = setup_organization();

    // Step 2: Alice accepts the invite
    if !prompt_user_to_verify_fingerprint(&org) {
        panic!("User did not verify organization fingerprint");
    }
    let (alice_signature, serialized_message, _signed_org_claim) =
        user_accepts_invite(&org, &alice);
    // upload: alice_signature, serialized_message, _signed_org_claim

    // Step 3: Admin confirms alice
    if !prompt_organization_to_verify_fingerprint(&alice) {
        panic!("Organization did not verify member fingerprint");
    }
    let (admin_signature, envelope, _signed_member_claim) =
        admin_confirms_join(&alice, &org, &alice_signature, &serialized_message);
    // upload: admin_signature, envelope, _signed_member_claim

    // Alice loads her vault, including the organization key
    let loaded_vault_key = load_shared_vault_key(
        &alice,
        &org,
        &admin_signature,
        &alice_signature,
        &serialized_message,
        &envelope,
    );
    assert_eq!(
        org.symmetric_key, loaded_vault_key,
        "Loaded key does not match original organization key"
    );
}
