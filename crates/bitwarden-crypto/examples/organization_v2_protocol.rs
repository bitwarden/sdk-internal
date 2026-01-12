//! Implements the V2 organization protocol, that enhances cryptographic guarantees with respect to
//! a compromised server. Over the V1 protocol, this decomposes the cryptography to establish trust
//! once and only once, to be able to use this trust for other objects such as policies, and to
//! implement a new key transport mechanism that allows key rotation, and also provides sender
//! authentication.

use bitwarden_crypto::{
    AsymmetricCryptoKey, DeriveFingerprint, KeyStore, PublicKeyEncryptionAlgorithm,
    SerializedMessage, Signature, SignatureAlgorithm, SignedObject, SignedPublicKey,
    SignedPublicKeyMessage, SigningKey, SigningNamespace, SymmetricCryptoKey, VerifyingKey,
    key_ids,
    safe::{IdentitySealedKeyEnvelope, OtherIdentity, SelfIdentity},
};
use serde::{Deserialize, Serialize};

// Define key IDs for the example
key_ids! {
    #[symmetric]
    pub enum ExampleSymmetricKey {
        OrgKey,
        #[local]
        VaultKey(LocalId)
    }

    #[asymmetric]
    pub enum ExampleAsymmetricKey {
        UserPrivateKey,
        OrgPrivateKey,
        #[local]
        Local(LocalId)
    }

    #[signing]
    pub enum ExampleSigningKey {
        UserSigningKey,
        OrgSigningKey,
        #[local]
        Local(LocalId)
    }

   pub ExampleIds => ExampleSymmetricKey, ExampleAsymmetricKey, ExampleSigningKey;
}

/// Represents a user's cryptographic identity
struct UserIdentity {
    name: String,
    key_store: KeyStore<ExampleIds>,
    /// Kept for deriving fresh VerifyingKey instances (since VerifyingKey doesn't implement Clone)
    signing_key_copy: SigningKey,
    signed_public_key: SignedPublicKey,
}

impl UserIdentity {
    fn verifying_key(&self) -> VerifyingKey {
        self.signing_key_copy.to_verifying_key()
    }
}

/// Represents an organization's cryptographic identity and key material
struct OrganizationIdentity {
    name: String,
    key_store: KeyStore<ExampleIds>,
    /// Kept for deriving fresh VerifyingKey instances (since VerifyingKey doesn't implement Clone)
    signing_key_copy: SigningKey,
    /// The organization's signed public key for identity verification
    signed_public_key: SignedPublicKey,
}

impl OrganizationIdentity {
    fn verifying_key(&self) -> VerifyingKey {
        self.signing_key_copy.to_verifying_key()
    }
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
    let key_store = KeyStore::<ExampleIds>::default();
    let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
    let signing_key_copy = signing_key.clone();
    let private_key = AsymmetricCryptoKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
    let signed_public_key = SignedPublicKeyMessage::from_public_key(&private_key.to_public_key())
        .expect("Failed to create signed public key message")
        .sign(&signing_key)
        .expect("Failed to sign public key");

    // Store keys in the key store (scope the context borrow)
    {
        let mut ctx = key_store.context_mut();
        #[allow(deprecated)]
        ctx.set_signing_key(ExampleSigningKey::UserSigningKey, signing_key);
        #[allow(deprecated)]
        ctx.set_asymmetric_key(ExampleAsymmetricKey::UserPrivateKey, private_key);
    }

    UserIdentity {
        name: "Alice".to_string(),
        key_store,
        signing_key_copy,
        signed_public_key,
    }
}

fn setup_organization() -> OrganizationIdentity {
    let key_store = KeyStore::<ExampleIds>::default();
    let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
    let signing_key_copy = signing_key.clone();
    let symmetric_key = SymmetricCryptoKey::make_xchacha20_poly1305_key();
    let private_key = AsymmetricCryptoKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
    let signed_public_key = SignedPublicKeyMessage::from_public_key(&private_key.to_public_key())
        .expect("Failed to create signed public key message")
        .sign(&signing_key)
        .expect("Failed to sign public key");

    // Store keys in the key store (scope the context borrow)
    {
        let mut ctx = key_store.context_mut();
        #[allow(deprecated)]
        ctx.set_signing_key(ExampleSigningKey::OrgSigningKey, signing_key);
        #[allow(deprecated)]
        ctx.set_symmetric_key(ExampleSymmetricKey::OrgKey, symmetric_key);
        #[allow(deprecated)]
        ctx.set_asymmetric_key(ExampleAsymmetricKey::OrgPrivateKey, private_key);
    }

    OrganizationIdentity {
        name: "My Org Name".to_string(),
        key_store,
        signing_key_copy,
        signed_public_key,
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
    let ctx = member.key_store.context();

    let identity_claim = IdentityClaim {
        identity_fingerprint: org.verifying_key().fingerprint(),
        identifier: org.name.to_string(),
    };

    // Get the signing key from context
    #[allow(deprecated)]
    let signing_key = ctx
        .dangerous_get_signing_key(ExampleSigningKey::UserSigningKey)
        .expect("Signing key should exist");

    // Admin signs the identity claim to assert ownership
    let signed_claim = signing_key
        .sign(&identity_claim, &SigningNamespace::IdentityClaim)
        .expect("Failed to sign identity claim");

    let membership_agreement = MembershipAgreement {
        member_identity: member.verifying_key().fingerprint(),
        organization_identity: org.verifying_key().fingerprint(),
    };

    let (signature, serialized_message) = signing_key
        .sign_detached(
            &membership_agreement,
            &SigningNamespace::MembershipAgreement,
        )
        .expect("Failed to sign membership agreement");
    (signature, serialized_message, signed_claim)
}

/// Step 3: Member verifies and counter-signs the membership agreement
/// NOTE: REQUIRES ADMIN TO FIRST CONFIRM THE MEMBERS NAME TO THE FINGERPRINT OUT-OF-BAND
/// Returns the counter-signature, signed member claim, OtherIdentity for member, and org symmetric key
fn admin_confirms_join(
    member: &UserIdentity,
    org: &OrganizationIdentity,
    signature: &Signature,
    serialized_message: &SerializedMessage,
) -> (
    Signature,
    SignedObject,
    OtherIdentity,
    IdentitySealedKeyEnvelope,
) {
    // Verify admin's signature
    assert!(
        signature.verify(
            serialized_message.as_bytes(),
            &member.verifying_key(),
            &SigningNamespace::MembershipAgreement,
        ),
        "Failed to verify admin's membership signature"
    );

    // Get the signing key from context
    let ctx = org.key_store.context();
    #[allow(deprecated)]
    let org_signing_key = ctx
        .dangerous_get_signing_key(ExampleSigningKey::OrgSigningKey)
        .expect("Org signing key should exist");

    let identity_claim = IdentityClaim {
        identity_fingerprint: member.verifying_key().fingerprint(),
        identifier: member.name.to_string(),
    };
    let signed_member_claim = org_signing_key
        .sign(&identity_claim, &SigningNamespace::IdentityClaim)
        .expect("Failed to sign member identity claim");

    // Counter-sign to indicate acceptance
    let counter_signature = org_signing_key
        .counter_sign_detached(
            serialized_message.as_bytes().to_vec(),
            signature,
            &SigningNamespace::MembershipAgreement,
        )
        .expect("Failed to counter-sign membership agreement");

    #[allow(deprecated)]
    let org_symmetric_key = ctx
        .dangerous_get_symmetric_key(ExampleSymmetricKey::OrgKey)
        .expect("Org symmetric key should exist")
        .clone();

    // Create OtherIdentity for the member to seal the key
    // This validates that the member's signed public key is authentic
    let member_identity =
        OtherIdentity::try_from((member.signed_public_key.clone(), member.verifying_key()))
            .expect("Failed to create member identity");
    let ctx = org.key_store.context_mut();
    let self_idenitty = SelfIdentity::new(
        &ctx,
        ExampleSigningKey::OrgSigningKey,
        ExampleAsymmetricKey::OrgPrivateKey,
    );
    let envelope =
        IdentitySealedKeyEnvelope::seal(&self_idenitty, &member_identity, &org_symmetric_key)
            .unwrap();

    (
        counter_signature,
        signed_member_claim,
        member_identity,
        envelope,
    )
}

/// Step 5: Member loads the organization key by verifying all signatures
/// Returns the OtherIdentity for the org for use with unseal
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
            &org.verifying_key(),
            &SigningNamespace::MembershipAgreement,
        ),
        "Failed to verify admin's membership signature"
    );
    assert!(
        member_signature.verify(
            serialized_message.as_bytes(),
            &member.verifying_key(),
            &SigningNamespace::MembershipAgreement,
        ),
        "Failed to verify member's membership signature"
    );

    let ctx = member.key_store.context();
    let self_identity = SelfIdentity::new(
        &ctx,
        ExampleSigningKey::UserSigningKey,
        ExampleAsymmetricKey::UserPrivateKey,
    );
    let org_identity =
        OtherIdentity::try_from((org.signed_public_key.clone(), org.verifying_key()))
            .expect("Failed to create organization identity");

    // Unseal the organization key
    let key = envelope
        .unseal(&self_identity, &org_identity)
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
    let (admin_signature, _signed_member_claim, _member_identity, envelope) =
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

    // Get the original org key to compare
    let org_ctx = org.key_store.context();
    #[allow(deprecated)]
    let original_org_key = org_ctx
        .dangerous_get_symmetric_key(ExampleSymmetricKey::OrgKey)
        .expect("Org key should exist");

    assert_eq!(
        *original_org_key, loaded_vault_key,
        "Loaded key does not match original organization key"
    );
}
