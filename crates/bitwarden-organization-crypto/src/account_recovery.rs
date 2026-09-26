//! Account recovery keys: a member's user key encapsulated to the organization's public key.
//!
//! A member enrolled in account recovery encapsulates their user key to the organization's public
//! key, and the organization stores the result on the membership. Opening it again requires the
//! organization's private key, which is stored wrapped with the organization key.

use bitwarden_crypto::{KeySlotIds, KeyStoreContext, UnsignedSharedKey};

use crate::organization_private_key::{OrganizationPrivateKey, OrganizationPrivateKeyError};

/// Decapsulates a member's user key from their account recovery key, returning the id it was
/// added to the context under.
pub fn decapsulate_member_user_key<Ids: KeySlotIds>(
    organization_private_key: &OrganizationPrivateKey<Ids>,
    account_recovery_key: &UnsignedSharedKey,
    ctx: &mut KeyStoreContext<Ids>,
) -> Result<Ids::Symmetric, OrganizationPrivateKeyError> {
    organization_private_key.decapsulate_key(account_recovery_key, ctx)
}

/// Encapsulates a member's user key to the organization, producing a new account recovery key.
pub fn encapsulate_member_user_key<Ids: KeySlotIds>(
    organization_private_key: &OrganizationPrivateKey<Ids>,
    member_user_key: Ids::Symmetric,
    ctx: &KeyStoreContext<Ids>,
) -> Result<UnsignedSharedKey, OrganizationPrivateKeyError> {
    organization_private_key.encapsulate_key(member_user_key, ctx)
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{
        EncString, KeyStore, KeyStoreContext, PublicKeyEncryptionAlgorithm,
        SymmetricKeyAlgorithm::Aes256CbcHmac, key_slot_ids,
    };

    use super::*;

    /// Sets the organization key and returns a fresh private key wrapped with it.
    fn make_organization_key_pair(ctx: &mut KeyStoreContext<'_, TestIds>) -> EncString {
        let local_org_key = ctx.make_symmetric_key(Aes256CbcHmac);
        ctx.persist_symmetric_key(local_org_key, TestSymmKey::Organization)
            .unwrap();

        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        ctx.wrap_private_key(TestSymmKey::Organization, private_key)
            .unwrap()
    }

    #[test]
    fn test_encapsulated_member_user_key_decapsulates_to_the_same_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = make_organization_key_pair(&mut ctx);
        let organization_private_key = OrganizationPrivateKey::unwrap_with_organization_key(
            TestSymmKey::Organization,
            &wrapped_private_key,
            &mut ctx,
        )
        .unwrap();

        let member_user_key = ctx.make_symmetric_key(Aes256CbcHmac);
        let account_recovery_key =
            encapsulate_member_user_key(&organization_private_key, member_user_key, &ctx).unwrap();
        let recovered =
            decapsulate_member_user_key(&organization_private_key, &account_recovery_key, &mut ctx)
                .unwrap();

        ctx.assert_symmetric_keys_equal(member_user_key, recovered);
    }

    #[test]
    fn test_decapsulating_a_key_encapsulated_to_another_organization_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = make_organization_key_pair(&mut ctx);
        let organization_private_key = OrganizationPrivateKey::unwrap_with_organization_key(
            TestSymmKey::Organization,
            &wrapped_private_key,
            &mut ctx,
        )
        .unwrap();

        let other_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let other_public_key = ctx.get_public_key(other_private_key).unwrap();
        let member_user_key = ctx.make_symmetric_key(Aes256CbcHmac);
        let account_recovery_key =
            UnsignedSharedKey::encapsulate(member_user_key, &other_public_key, &ctx).unwrap();

        let result =
            decapsulate_member_user_key(&organization_private_key, &account_recovery_key, &mut ctx);

        assert!(matches!(
            result,
            Err(OrganizationPrivateKeyError::DecapsulationFailed)
        ));
    }

    key_slot_ids! {
        #[symmetric]
        pub enum TestSymmKey {
            Organization,
            #[local]
            Local(LocalId),
        }

        #[private]
        pub enum TestPrivateKey {
            Organization,
            #[local]
            Local(LocalId),
        }

        #[signing]
        pub enum TestSigningKey {
            Organization,
            #[local]
            Local(LocalId),
        }

        pub TestIds => TestSymmKey, TestPrivateKey, TestSigningKey;
    }
}
