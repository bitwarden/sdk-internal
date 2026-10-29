//! This example demonstrates the account recovery lifecycle: the organization enables account
//! recovery for a member, the member enrolls into account recovery, and an admin recovers the
//! member's account by resetting the member's master password.

use bitwarden_crypto::{
    EncString, KeyStore, KeyStoreContext, PublicKey, PublicKeyEncryptionAlgorithm,
    SymmetricKeyAlgorithm::Aes256CbcHmac, key_slot_ids,
};
use bitwarden_organization_crypto::{
    account_recovery::{AccountRecovery, AccountRecoveryMakeError},
    invite::Invite,
    organization_private_key::OrganizationPrivateKey,
    trust_proof::TrustProof,
};

fn main() {
    let key_store = KeyStore::<ExampleIds>::default();
    let mut ctx: KeyStoreContext<'_, ExampleIds> = key_store.context_mut();
    let org_id = uuid::Uuid::default();

    let (org_key, wrapped_org_private_key, server_org_public_key) =
        create_organization(org_id, &mut ctx);

    // The member's user key. In the SDK, it is in the key store after unlock.
    let member_user_key = ctx.make_symmetric_key(Aes256CbcHmac);

    // 1. The organization enables account recovery for the member. The member enrolls only with an
    // organization public key that they trust. Here, the trust comes from an invite, which binds
    // the thumbprint of the organization public key. The invite secret reaches the member in the
    // invite link, outside the server.
    let (invite_secret, invite) =
        Invite::make_for_private_key(org_key, &wrapped_org_private_key, &mut ctx)
            .expect("generating an invite should work");

    // 2. The member enrolls into account recovery. The server supplies the organization public key.
    // The member trusts it only if it matches the thumbprint bound into the invite.
    let invite_key = invite
        .unseal_invite_key_with_invite_secret(&invite_secret, &mut ctx)
        .expect("the member should recover the invite key from the invite secret");
    let bound_thumbprint = invite
        .get_public_key_thumbprint(invite_key, &mut ctx)
        .expect("recovering the bound thumbprint should work");
    let account_recovery = AccountRecovery::make(
        member_user_key,
        &server_org_public_key,
        &TrustProof::ManuallyTrusted(bound_thumbprint.clone()),
        &ctx,
    )
    .expect("enrolling into account recovery should work");

    // A public key that the server swapped does not match the bound thumbprint, so the member's
    // user key is not shared with it.
    let swapped_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
    let swapped_public_key = ctx
        .get_public_key(swapped_private_key)
        .expect("getting the swapped public key should work");
    let result = AccountRecovery::make(
        member_user_key,
        &swapped_public_key,
        &TrustProof::ManuallyTrusted(bound_thumbprint),
        &ctx,
    );
    assert!(matches!(
        result,
        Err(AccountRecoveryMakeError::UntrustedPublicKey)
    ));

    // 3. The account recovery is sent to the server as a string, the "reset password key" of the
    // membership.
    let stored_account_recovery = String::from(&account_recovery);

    // 4. An admin recovers the member's account by resetting the member's master password. The
    // admin unwraps the organization private key with the organization key, and unseals the
    // member's user key from the account recovery that the server returns.
    let account_recovery: AccountRecovery = stored_account_recovery
        .parse()
        .expect("the account recovery round-trips through its string form");
    let org_private_key = OrganizationPrivateKey::unwrap_with_organization_key(
        org_key,
        &wrapped_org_private_key,
        &mut ctx,
    )
    .expect("unwrapping the org private key should work");
    let recovered_member_user_key = account_recovery
        .unseal_member_user_key(&org_private_key, &mut ctx)
        .expect("the admin should recover the member's user key");
    ctx.assert_symmetric_keys_equal(recovered_member_user_key, member_user_key);

    // The admin then wraps the recovered user key with a key derived from the member's new master
    // password, and shares the wrapped user key with the server. The member logs in with the new
    // master password, which unwraps the user key and recovers the account. In the SDK,
    // `bitwarden-core` derives this master password unlock data.
}

/// Creates the organization key, and the organization key pair whose private key is wrapped with
/// the organization key. The server stores the wrapped private key and supplies the public key.
fn create_organization(
    org_id: uuid::Uuid,
    ctx: &mut KeyStoreContext<'_, ExampleIds>,
) -> (ExampleSymmetricKey, EncString, PublicKey) {
    let org_key = ExampleSymmetricKey::Organization(org_id);
    let local_org_key = ctx.make_symmetric_key(Aes256CbcHmac);
    ctx.persist_symmetric_key(local_org_key, org_key)
        .expect("switching key ids should work");
    let org_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
    let wrapped_org_private_key = ctx
        .wrap_private_key(org_key, org_private_key)
        .expect("wrapping the private key with the org key should work");
    let org_public_key = ctx
        .get_public_key(org_private_key)
        .expect("getting the org public key should work");
    (org_key, wrapped_org_private_key, org_public_key)
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
