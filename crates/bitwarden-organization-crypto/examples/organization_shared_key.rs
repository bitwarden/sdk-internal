//! This example demonstrates how the organization key is shared with members: the owner sharing it
//! with their own key pair, and an admin confirming a member.

use bitwarden_crypto::{
    CoseKeyThumbprintExt, KeyStore, KeyStoreContext, PublicKeyEncryptionAlgorithm,
    SymmetricKeyAlgorithm::Aes256CbcHmac, key_slot_ids,
};
use bitwarden_organization_crypto::{
    organization_shared_key::OrganizationSharedKey,
    trust_proof::{CryptographicProof, TrustProof},
};

fn main() {
    let key_store = KeyStore::<ExampleIds>::default();
    let mut ctx: KeyStoreContext<'_, ExampleIds> = key_store.context_mut();
    let org_id = uuid::Uuid::default();

    // The owner's and the member's account key pairs. In the SDK, they are in the key store after
    // unlock.
    let owner_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
    let member_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);

    // 1. The owner creates the organization key.
    let org_key = ExampleSymmetricKey::Organization(org_id);
    let local_org_key = ctx.make_symmetric_key(Aes256CbcHmac);
    ctx.persist_symmetric_key(local_org_key, org_key)
        .expect("switching key ids should work");

    // 2. The owner shares the organization key with their own key pair. The owner holds the
    // matching private key, which proves that the public key is theirs.
    let owner_public_key = ctx
        .get_public_key(owner_private_key)
        .expect("getting the owner's public key should work");
    let owner_shared_key = OrganizationSharedKey::make(
        org_key,
        &owner_public_key,
        &TrustProof::CryptographicallyTrusted(CryptographicProof::OwnPrivateKey(owner_private_key)),
        &ctx,
    )
    .expect("sharing the org key with the owner should work");

    // 3. An admin confirms the member. The server supplies the member's public key, and the admin
    // trusts it after comparing the member's fingerprint.
    let server_member_public_key = ctx
        .get_public_key(member_private_key)
        .expect("getting the member's public key should work");
    let verified_member_thumbprint = server_member_public_key
        .thumbprint()
        .expect("computing the thumbprint should work");
    let member_shared_key = OrganizationSharedKey::make(
        org_key,
        &server_member_public_key,
        &TrustProof::ManuallyTrusted(verified_member_thumbprint),
        &ctx,
    )
    .expect("sharing the org key with the member should work");

    // 4. The shared key is sent to the server as a string, the `key` of the membership.
    let member_shared_key: OrganizationSharedKey = String::from(&member_shared_key)
        .parse()
        .expect("the shared key round-trips through its string form");

    // 5. The owner and the member unseal the organization key with their own private keys.
    let owner_org_key = owner_shared_key
        .unseal(owner_private_key, &mut ctx)
        .expect("the owner should unseal the org key");
    ctx.assert_symmetric_keys_equal(owner_org_key, org_key);
    let member_org_key = member_shared_key
        .unseal(member_private_key, &mut ctx)
        .expect("the member should unseal the org key");
    ctx.assert_symmetric_keys_equal(member_org_key, org_key);
}

key_slot_ids! {
    #[symmetric]
    pub enum ExampleSymmetricKey {
        Organization(uuid::Uuid),
        #[local]
        LocalKey(LocalId),
    }

    #[private]
    pub enum ExamplePrivateKey {
        Organization(uuid::Uuid),
        #[local]
        LocalKey(LocalId),
    }

    #[signing]
    pub enum ExampleSigningKey {
        Organization(uuid::Uuid),
        #[local]
        LocalKey(LocalId),
    }

    pub ExampleIds => ExampleSymmetricKey, ExamplePrivateKey, ExampleSigningKey;
}
