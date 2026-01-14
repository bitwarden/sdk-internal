//! Implements the V2 organization protocol, that enhances cryptographic guarantees with respect to
//! a compromised server. Over the V1 protocol, this decomposes the cryptography to establish trust
//! once and only once, to be able to use this trust for other objects such as policies, and to
//! implement a new key transport mechanism that allows key rotation, and also provides sender
//! authentication.

use bitwarden_crypto::{
    AsymmetricCryptoKey, DeriveFingerprint, KeyStore, KeyStoreContext,
    PublicKeyEncryptionAlgorithm, SerializedMessage, Signature, SignatureAlgorithm, SignedObject,
    SignedPublicKeyMessage, SigningKey, SigningNamespace, SymmetricCryptoKey, key_ids,
    safe::{IdentitySealedKeyEnvelope, OtherIdentity, SelfIdentity},
};
use serde::{Deserialize, Serialize};

/// Represents a user's cryptographic identity
struct UserIdentity {
    name: String,
}

impl UserIdentity {
    fn self_identity<'a>(
        &self,
        ctx: &'a KeyStoreContext<'a, ExampleIds>,
    ) -> SelfIdentity<'a, ExampleIds> {
        SelfIdentity::new(
            ctx,
            ExampleSigningKey::UserSigningKey,
            ExampleAsymmetricKey::UserPrivateKey,
        )
    }

    fn other_identity(&self, ctx: &KeyStoreContext<'_, ExampleIds>) -> OtherIdentity {
        let verifying_key = ctx
            .get_verifying_key(ExampleSigningKey::UserSigningKey)
            .expect("Signing key should exist");
        let signed_public_key = SignedPublicKeyMessage::from_public_key(
            &ctx.get_public_key(ExampleAsymmetricKey::UserPrivateKey)
                .expect("Private key should exist"),
        )
        .expect("Failed to create signed public key message")
        .sign(
            #[allow(deprecated)]
            &ctx.dangerous_get_signing_key(ExampleSigningKey::UserSigningKey)
                .expect("Signing key should exist"),
        )
        .expect("Failed to sign public key");
        OtherIdentity::try_from((signed_public_key, verifying_key))
            .expect("Failed to create other identity")
    }
}

/// Represents an organization's cryptographic identity and key material
struct OrganizationIdentity {
    name: String,
}

impl OrganizationIdentity {
    fn self_identity<'a>(
        &self,
        ctx: &'a KeyStoreContext<'a, ExampleIds>,
    ) -> SelfIdentity<'a, ExampleIds> {
        SelfIdentity::new(
            ctx,
            ExampleSigningKey::OrgSigningKey,
            ExampleAsymmetricKey::OrgPrivateKey,
        )
    }

    fn other_identity(&self, ctx: &KeyStoreContext<'_, ExampleIds>) -> OtherIdentity {
        let verifying_key = ctx
            .get_verifying_key(ExampleSigningKey::OrgSigningKey)
            .expect("Signing key should exist");
        let signed_public_key = SignedPublicKeyMessage::from_public_key(
            &ctx.get_public_key(ExampleAsymmetricKey::OrgPrivateKey)
                .expect("Private key should exist"),
        )
        .expect("Failed to create signed public key message")
        .sign(
            #[allow(deprecated)]
            &ctx.dangerous_get_signing_key(ExampleSigningKey::OrgSigningKey)
                .expect("Signing key should exist"),
        )
        .expect("Failed to sign public key");
        OtherIdentity::try_from((signed_public_key, verifying_key))
            .expect("Failed to create other identity")
    }
}

/// A claim that an identity belongs to a specific identifier (e.g., email, organization name)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IdentityClaim {
    identity_fingerprint: bitwarden_crypto::KeyFingerprint,
    identifier: String,
}

impl IdentityClaim {
    fn new(identity: OtherIdentity, identifier: String) -> Self {
        Self {
            identity_fingerprint: identity.fingerprint(),
            identifier,
        }
    }
}

/// An agreement between a member and an organization, signed by both parties
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MembershipAgreement {
    member_identity: bitwarden_crypto::KeyFingerprint,
    organization_identity: bitwarden_crypto::KeyFingerprint,
}

impl MembershipAgreement {
    fn new(member_identity: OtherIdentity, organization_identity: OtherIdentity) -> Self {
        Self {
            member_identity: member_identity.fingerprint(),
            organization_identity: organization_identity.fingerprint(),
        }
    }
}

fn setup_user(ctx: &mut KeyStoreContext<'_, ExampleIds>) -> UserIdentity {
    let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
    let private_key = AsymmetricCryptoKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);

    // Store keys in the key store (scope the context borrow)
    #[allow(deprecated)]
    let _ = ctx.set_signing_key(ExampleSigningKey::UserSigningKey, signing_key);
    #[allow(deprecated)]
    let _ = ctx.set_asymmetric_key(ExampleAsymmetricKey::UserPrivateKey, private_key);

    UserIdentity {
        name: "Alice".to_string(),
    }
}

fn setup_organization(ctx: &mut KeyStoreContext<'_, ExampleIds>) -> OrganizationIdentity {
    let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
    let symmetric_key = SymmetricCryptoKey::make_xchacha20_poly1305_key();
    let private_key = AsymmetricCryptoKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1);

    // Store keys in the key store (scope the context borrow)
    #[allow(deprecated)]
    let _ = ctx.set_signing_key(ExampleSigningKey::OrgSigningKey, signing_key);
    #[allow(deprecated)]
    let _ = ctx.set_symmetric_key(ExampleSymmetricKey::OrgKey, symmetric_key);
    #[allow(deprecated)]
    let _ = ctx.set_asymmetric_key(ExampleAsymmetricKey::OrgPrivateKey, private_key);

    OrganizationIdentity {
        name: "My Org Name".to_string(),
    }
}

// placeholder for out-of-band fingerprint verification
fn prompt_user_to_verify_fingerprint(_org: &OrganizationIdentity) -> bool {
    true
}

// placeholder for out-of-band fingerprint verification
fn prompt_organization_to_verify_fingerprint(_member: &UserIdentity) -> bool {
    true
}

/// Step 2: User accepts the invite by signing an identity claim and receiving a membership
/// agreement NOTE: REQUIRES OUT-OF-BAND VERIFICATION OF THE ORGANIZATION'S IDENTITY FINGERPRINT
fn user_accepts_invite(
    org: &OrganizationIdentity,
    member: &UserIdentity,
    ctx: &KeyStoreContext<'_, ExampleIds>,
) -> (Signature, SerializedMessage, SignedObject) {
    let identity_claim = IdentityClaim {
        identity_fingerprint: org.other_identity(ctx).fingerprint(),
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

    let membership_agreement =
        MembershipAgreement::new(member.other_identity(ctx), org.other_identity(ctx));

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
/// Returns the counter-signature, signed member claim, OtherIdentity for member, and org symmetric
/// key
fn admin_confirms_join(
    member: &UserIdentity,
    org: &OrganizationIdentity,
    signature: &Signature,
    serialized_message: &SerializedMessage,
    ctx: &KeyStoreContext<'_, ExampleIds>,
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
            &member.other_identity(ctx).verifying_key(),
            &SigningNamespace::MembershipAgreement,
        ),
        "Failed to verify admin's membership signature"
    );

    // Get the signing key from context
    #[allow(deprecated)]
    let org_signing_key = ctx
        .dangerous_get_signing_key(ExampleSigningKey::OrgSigningKey)
        .expect("Org signing key should exist");

    let identity_claim = IdentityClaim::new(member.other_identity(ctx), member.name.to_string());
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
    let member_identity = member.other_identity(ctx);
    let self_identity = org.self_identity(ctx);
    let envelope =
        IdentitySealedKeyEnvelope::seal(&self_identity, &member_identity, &org_symmetric_key)
            .expect("Failed to seal organization key");

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
    ctx: &KeyStoreContext<'_, ExampleIds>,
) -> SymmetricCryptoKey {
    // Verify both signatures on the membership agreement
    assert!(
        admin_signature.verify(
            serialized_message.as_bytes(),
            &org.other_identity(ctx).verifying_key(),
            &SigningNamespace::MembershipAgreement,
        ),
        "Failed to verify admin's membership signature"
    );
    assert!(
        member_signature.verify(
            serialized_message.as_bytes(),
            &member.other_identity(ctx).verifying_key(),
            &SigningNamespace::MembershipAgreement,
        ),
        "Failed to verify member's membership signature"
    );

    let self_identity = member.self_identity(ctx);
    let org_identity = org.other_identity(ctx);
    envelope
        .unseal(&self_identity, &org_identity)
        .expect("Failed to unseal organization key")
}

fn main() {
    // Setup identities
    let key_store = KeyStore::<ExampleIds>::default();
    let mut ctx = key_store.context_mut();
    let user = setup_user(&mut ctx);
    let org = setup_organization(&mut ctx);

    // Step 2: Alice accepts the invite
    if !prompt_user_to_verify_fingerprint(&org) {
        panic!("User did not verify organization fingerprint");
    }
    let (alice_signature, serialized_message, _signed_org_claim) =
        user_accepts_invite(&org, &user, &ctx);
    // upload: alice_signature, serialized_message, _signed_org_claim

    // Step 3: Admin confirms alice
    if !prompt_organization_to_verify_fingerprint(&user) {
        panic!("Organization did not verify member fingerprint");
    }
    let (admin_signature, _signed_member_claim, _member_identity, envelope) =
        admin_confirms_join(&user, &org, &alice_signature, &serialized_message, &ctx);
    // upload: admin_signature, envelope, _signed_member_claim

    // Alice loads her vault, including the organization key
    let loaded_vault_key = load_shared_vault_key(
        &user,
        &org,
        &admin_signature,
        &alice_signature,
        &serialized_message,
        &envelope,
        &ctx,
    );
    println!(
        "Successfully loaded organization vault key: {:?}",
        loaded_vault_key
    );
}

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
