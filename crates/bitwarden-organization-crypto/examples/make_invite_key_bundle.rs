//! This example demonstrates how to make a new invite key bundle
//! wrapped with the organization key using the [`InviteKeyBundle`]

use bitwarden_crypto::{KeyStore, KeyStoreContext, key_slot_ids};
use bitwarden_encoding::B64Url;
use bitwarden_organization_crypto::InviteKeyBundle;

fn main() {
    let key_store = KeyStore::<ExampleIds>::default();
    let mut ctx: KeyStoreContext<'_, ExampleIds> = key_store.context_mut();
    let org_id = uuid::Uuid::default();

    // for the sdk, this is automatically done during initialization by
    // `init_org`.
    let organization_key = ctx.generate_symmetric_key();
    ctx.persist_symmetric_key(organization_key, ExampleSymmetricKey::Organization(org_id))
        .expect("switching key ids should work");

    let bundle = InviteKeyBundle::make(ExampleSymmetricKey::Organization(org_id), &mut ctx)
        .expect("generating an invitation key bundle should work");

    let bytes = bundle.raw_invite_key();
    let organization_wrapped_invitation_key = bundle.organization_wrapped_invite_key();

    let unwrapped_key_id = ctx
        .unwrap_symmetric_key(organization_key, organization_wrapped_invitation_key)
        .expect("unwrapping should work");

    // Testing purposes only
    // DO NOT REPLICATE
    #[allow(deprecated)]
    let decrypted_bytes = B64Url::from(
        ctx.dangerous_get_symmetric_key(unwrapped_key_id)
            .expect("getting key bytes from keystore should work")
            .to_encoded()
            .as_ref(),
    );

    assert_eq!(bytes, decrypted_bytes)
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
