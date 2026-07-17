//! This example demonstrates the full lifecycle of an organization invite,
//! creating it, reconstructing the invite link (admin), confirm-joining (invitee), and enabling
//! account recovery (verifying the organization public key bound into the invite).

use bitwarden_crypto::{
    CoseKeyThumbprintExt, KeyStore, KeyStoreContext, PublicKeyEncryptionAlgorithm,
    SymmetricKeyAlgorithm::Aes256CbcHmac, key_slot_ids,
};
use bitwarden_organization_crypto::invite::{Invite, InviteSecret};

fn main() {
    let key_store = KeyStore::<ExampleIds>::default();
    let mut ctx: KeyStoreContext<'_, ExampleIds> = key_store.context_mut();
    let org_id = uuid::Uuid::default();

    // For the sdk, this is automatically done during initialization by
    // `init_org`. Persisting moves the key into the organization slot, so all invite operations
    // reference it by that global id.
    let org_key = ExampleSymmetricKey::Organization(org_id);
    let local_org_key = ctx.make_symmetric_key(Aes256CbcHmac);
    ctx.persist_symmetric_key(local_org_key, org_key)
        .expect("switching key ids should work");

    // The invite binds the organization public-key thumbprint, derived from the organization's
    // (wrapped) private key. Here we make an organization key pair and wrap the private key with
    // the organization key, as `make_for_private_key` expects.
    let org_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
    let thumbprint = ctx
        .get_public_key(org_private_key)
        .expect("getting the public key should work")
        .thumbprint()
        .expect("computing the thumbprint should work");
    let wrapped_private_key = ctx
        .wrap_private_key(org_key, org_private_key)
        .expect("wrapping the private key with the org key should work");

    // 1. Create an invite. `make_for_private_key` returns two parts as a tuple.
    let (secret, invite): (InviteSecret, Invite) =
        Invite::make_for_private_key(org_key, &wrapped_private_key, &mut ctx)
            .expect("generating an invite should work");

    // 2. The first part is the `InviteSecret`: the raw URL-fragment secret carried in the invite
    // link. `InviteSecret` automatically serializes to `B64Url` when used in WASM bindings, or use
    // `String::from(&invite_secret)` to manually generate a base64Url-encoded string.
    //
    // CRITICAL: this object must never be shared with the server.

    // 3. The second part is the `Invite`. This is the server-safe bundle of wrapped envelopes. It
    // serializes to a base64-encoded JSON structure via serde, `String::from(&invite)`, or wasm abi
    // serialization.
    //
    // This can be sent to the server, and should be persisted there:
    // ```
    // { // Request model
    //   "invite": "abcdef==",
    //   "otherData":...
    // }
    // ```

    // 4. Admin direction: recover the invite key from the organization key, then use it to recover
    // the invite secret, e.g. to reconstruct an invite link.
    let invite_key = invite
        .unseal_invite_key_with_organization_key(org_key, &mut ctx)
        .expect("recovering the invite key from the org key should work");
    let recovered_secret = invite
        .get_invite_secret(invite_key, &mut ctx)
        .expect("recovering the invite secret should work");
    assert_eq!(&secret, &recovered_secret);
    assert_eq!(String::from(&secret), String::from(&recovered_secret));

    // 5. Confirm-joining (invitee direction): an invitee holds ONLY the invite secret from the
    // link. From it they recover the invite key, and from the invite key the organization key,
    // without ever seeing the organization key beforehand. No verification is performed here.
    let invitee_secret: InviteSecret = String::from(&secret)
        .parse()
        .expect("the invite secret round-trips through its base64url form");
    let invitee_invite_key = invite
        .unseal_invite_key_with_invite_secret(&invitee_secret, &mut ctx)
        .expect("an invitee should recover the invite key from the invite secret");
    let recovered_org_key_id = invite
        .unseal_organization_key(invitee_invite_key, &mut ctx)
        .expect("an invitee should recover the organization key from the invite key");
    ctx.assert_symmetric_keys_equal(recovered_org_key_id, org_key);

    // 6. Enabling account recovery: recover the invite key from the organization key, read the
    // organization public-key thumbprint bound into the invite, and confirm it matches the
    // organization public key we are about to enroll against. A substituted public key would not
    // match, so the organization key cannot be captured by an attacker-supplied recovery key.
    let recovery_invite_key = invite
        .unseal_invite_key_with_organization_key(org_key, &mut ctx)
        .expect("recovering the invite key from the org key should work");
    let bound_thumbprint = invite
        .get_public_key_thumbprint(recovery_invite_key, &mut ctx)
        .expect("recovering the bound thumbprint should work");
    assert_eq!(bound_thumbprint, thumbprint);
    // (In the SDK, `InviteLinkClient::enroll_account_recovery` performs exactly this check before
    // encapsulating the organization key to the recovery public key.)
}

key_slot_ids! {
    #[symmetric]
    pub enum ExampleSymmetricKey {
        UserId,
        Organization(uuid::Uuid),
        #[local]
        LocalKey(LocalId),
    }

    #[private]
    pub enum ExamplePrivateKey {
        UserId,
        Organization(uuid::Uuid),
        #[local]
        LocalKey(LocalId),
    }

    #[signing]
    pub enum ExampleSigningKey {
        UserId,
        Organization(uuid::Uuid),
        #[local]
        LocalKey(LocalId),
    }

    pub ExampleIds => ExampleSymmetricKey, ExamplePrivateKey, ExampleSigningKey;
}
