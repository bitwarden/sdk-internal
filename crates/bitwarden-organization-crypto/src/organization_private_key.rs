//! The organization's key pair, held in a key store context.
//!
//! The organization's private key is stored wrapped with the organization key. Unwrapping it
//! gives a handle that encapsulates keys to the organization, and opens keys that were
//! encapsulated to it.

use bitwarden_crypto::{EncString, KeySlotIds, KeyStoreContext, PublicKey, UnsignedSharedKey};
use thiserror::Error;

/// Errors that can occur when using the organization's private key.
#[derive(Debug, Error)]
pub enum OrganizationPrivateKeyError {
    /// The organization's private key could not be unwrapped with the organization key
    #[error("Invalid organization private key")]
    InvalidPrivateKey,
    /// The key could not be opened with the organization's private key
    #[error("Unable to decapsulate the key")]
    DecapsulationFailed,
}

/// The organization's private key, unwrapped into the key store context.
pub struct OrganizationPrivateKey<Ids: KeySlotIds> {
    private_key_id: Ids::Private,
}

impl<Ids: KeySlotIds> OrganizationPrivateKey<Ids> {
    /// Unwraps the organization's private key with the organization key.
    ///
    /// `wrapped_organization_private_key` is the value the server stores on the organization.
    pub fn unwrap_with_organization_key(
        organization_key: Ids::Symmetric,
        wrapped_organization_private_key: &EncString,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Self, OrganizationPrivateKeyError> {
        let private_key_id = ctx
            .unwrap_private_key(organization_key, wrapped_organization_private_key)
            .map_err(|_| OrganizationPrivateKeyError::InvalidPrivateKey)?;

        Ok(Self { private_key_id })
    }

    /// The organization's public key.
    pub fn public_key(
        &self,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<PublicKey, OrganizationPrivateKeyError> {
        ctx.get_public_key(self.private_key_id)
            .map_err(|_| OrganizationPrivateKeyError::InvalidPrivateKey)
    }

    /// Opens a key that was encapsulated to the organization, returning the id it was added to the
    /// context under.
    pub fn decapsulate_key(
        &self,
        encapsulated_key: &UnsignedSharedKey,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, OrganizationPrivateKeyError> {
        encapsulated_key
            .decapsulate(self.private_key_id, ctx)
            .map_err(|_| OrganizationPrivateKeyError::DecapsulationFailed)
    }
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
    fn test_unwrapping_with_the_wrong_organization_key_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = make_organization_key_pair(&mut ctx);
        let other_organization_key = ctx.make_symmetric_key(Aes256CbcHmac);

        let result = OrganizationPrivateKey::unwrap_with_organization_key(
            other_organization_key,
            &wrapped_private_key,
            &mut ctx,
        );

        assert!(matches!(
            result,
            Err(OrganizationPrivateKeyError::InvalidPrivateKey)
        ));
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
        let key = ctx.make_symmetric_key(Aes256CbcHmac);
        let encapsulated_key =
            UnsignedSharedKey::encapsulate(key, &other_public_key, &ctx).unwrap();

        let result = organization_private_key.decapsulate_key(&encapsulated_key, &mut ctx);

        assert!(matches!(
            result,
            Err(OrganizationPrivateKeyError::DecapsulationFailed)
        ));
    }

    #[test]
    fn test_a_key_encapsulated_to_the_public_key_decapsulates_to_the_same_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let wrapped_private_key = make_organization_key_pair(&mut ctx);
        let organization_private_key = OrganizationPrivateKey::unwrap_with_organization_key(
            TestSymmKey::Organization,
            &wrapped_private_key,
            &mut ctx,
        )
        .unwrap();

        let key = ctx.make_symmetric_key(Aes256CbcHmac);
        let public_key = organization_private_key.public_key(&ctx).unwrap();
        let encapsulated_key = UnsignedSharedKey::encapsulate(key, &public_key, &ctx).unwrap();
        let recovered = organization_private_key
            .decapsulate_key(&encapsulated_key, &mut ctx)
            .unwrap();

        ctx.assert_symmetric_keys_equal(key, recovered);
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
