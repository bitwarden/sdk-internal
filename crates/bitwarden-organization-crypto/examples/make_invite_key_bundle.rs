//! This example demonstrates how to make a new invite key bundle
//! sealed with the organization key using the [`InviteKeyBundle`]

use bitwarden_crypto::{
    KeyStore, KeyStoreContext, SymmetricKeyAlgorithm::Aes256CbcHmac, key_slot_ids,
};
use bitwarden_organization_crypto::{Invite, InviteBundle, InviteKeyData};

fn main() {
    let key_store = KeyStore::<ExampleIds>::default();
    let mut ctx: KeyStoreContext<'_, ExampleIds> = key_store.context_mut();
    let org_id = uuid::Uuid::default();

    // For the sdk, this is automatically done during initialization by
    // `init_org`.
    let organization_key = ctx.make_symmetric_key(Aes256CbcHmac);
    ctx.persist_symmetric_key(organization_key, ExampleSymmetricKey::Organization(org_id))
        .expect("switching key ids should work");

    // 1. Create an `InviteKeyBundle`, each bundle consists of two parts.
    let bundle = InviteBundle::make(ExampleSymmetricKey::Organization(org_id), &mut ctx)
        .expect("generating an invitation key bundle should work");

    // 2. The first part is an `InviteKeyData`. This represents the raw Invite
    // Key bytes. `InviteKeyData` automatically serializes to `B64Url` when used
    // in WASM bindings. Or use `String::from(&invite_key_data)` to manually
    // generate a base64Url-encoded string.
    //
    // This method is named dangerous because it is critical this object is not
    // shared with the server.
    let key: &InviteKeyData = bundle.dangerous_get_raw_invite_key();

    // 3. The second part is `InviteKeyEnvelope`. This is the invite
    // key sealed by the org key. `InviteKeyEnvelope` serializes to the
    // Bitwarden EncString text format (`"2.iv|data|mac"`) when using serde,
    // `String::from(&inviteKeyEnvelope)`, or wasm abi serialization.
    //
    // This can be sent to the server, and should be persisted there:
    // ```
    // { // Request model
    //   "inviteKeyEnvelope": "abcdef==",
    //   "otherData":...
    // }
    // ```
    let invite_key_envelope: &Invite = bundle.get_envelope();

    // 4. Given a sealed `InviteKeyEnvelope` and an organization key, it may
    // be necessary to unseal and access the inner InviteKey, e.g. to implement
    // `reconstructUrl`. The `InviteKeyEnvelope` provides an easy interface for
    // transforming `InviteKeyEnvelope` => `InviteKeyData`
    let unsealed_key = invite_key_envelope
        .unseal(organization_key, &mut ctx)
        .expect("unsealing should work");

    assert_eq!(key, &unsealed_key);
    assert_eq!(String::from(key), String::from(&unsealed_key));
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
