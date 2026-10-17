//! Account recovery keys: a member's user key encapsulated to the organization's public key.
//!
//! A member enrolled in account recovery encapsulates their user key to the organization's public
//! key, and the organization stores the result on the membership. Opening it again requires the
//! organization's private key, which is stored wrapped with the organization key.

use std::{fmt::Display, str::FromStr};

use bitwarden_crypto::{KeySlotIds, KeyStoreContext, PublicKey, UnsignedSharedKey};
use thiserror::Error;

use crate::organization_private_key::OrganizationPrivateKey;

/// Errors that can occur when reading or producing an account recovery key.
#[derive(Debug, Error)]
pub enum AccountRecoveryKeyError {
    /// The stored account recovery key is in no known format
    #[error("Malformed account recovery key")]
    Malformed,
    /// The member's user key could not be encapsulated to the organization
    #[error("Unable to encapsulate the member's user key")]
    EncapsulationFailed,
    /// The member's user key could not be opened with the organization's private key
    #[error("Unable to recover the member's user key")]
    DecapsulationFailed,
}

/// A member's user key, held by the organization so that admins can recover the account.
///
/// The variant names the format of the account recovery key.
pub enum AccountRecoveryKey {
    /// The member's user key encapsulated to the organization's public key.
    V1(UnsignedSharedKey),
}

impl AccountRecoveryKey {
    /// Encapsulates a member's user key to the organization's public key.
    ///
    /// Encapsulation authenticates no sender, so the caller must trust the public key. A swapped
    /// public key hands the member's user key to whoever holds the matching private key.
    pub fn encapsulate<Ids: KeySlotIds>(
        member_user_key: Ids::Symmetric,
        organization_public_key: &PublicKey,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, AccountRecoveryKeyError> {
        let encapsulated_key =
            UnsignedSharedKey::encapsulate(member_user_key, organization_public_key, ctx)
                .map_err(|_| AccountRecoveryKeyError::EncapsulationFailed)?;

        Ok(Self::V1(encapsulated_key))
    }

    /// Opens the member's user key, returning the id it was added to the context under.
    pub fn decapsulate_member_user_key<Ids: KeySlotIds>(
        &self,
        organization_private_key: &OrganizationPrivateKey<Ids>,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, AccountRecoveryKeyError> {
        let Self::V1(encapsulated_key) = self;

        organization_private_key
            .decapsulate_key(encapsulated_key, ctx)
            .map_err(|_| AccountRecoveryKeyError::DecapsulationFailed)
    }
}

impl FromStr for AccountRecoveryKey {
    type Err = AccountRecoveryKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .parse()
            .map(Self::V1)
            .map_err(|_| AccountRecoveryKeyError::Malformed)
    }
}

impl Display for AccountRecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self::V1(encapsulated_key) = self;

        encapsulated_key.fmt(f)
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
        let account_recovery_key = AccountRecoveryKey::encapsulate(
            member_user_key,
            &organization_private_key.public_key(&ctx).unwrap(),
            &ctx,
        )
        .unwrap();
        let recovered = account_recovery_key
            .decapsulate_member_user_key(&organization_private_key, &mut ctx)
            .unwrap();

        ctx.assert_symmetric_keys_equal(member_user_key, recovered);
    }

    #[test]
    fn test_account_recovery_key_survives_a_string_round_trip() {
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
        let account_recovery_key = AccountRecoveryKey::encapsulate(
            member_user_key,
            &organization_private_key.public_key(&ctx).unwrap(),
            &ctx,
        )
        .unwrap();

        let parsed: AccountRecoveryKey = account_recovery_key.to_string().parse().unwrap();

        let recovered = parsed
            .decapsulate_member_user_key(&organization_private_key, &mut ctx)
            .unwrap();
        ctx.assert_symmetric_keys_equal(member_user_key, recovered);
    }

    #[test]
    fn test_parsing_a_key_in_no_known_format_fails() {
        let result: Result<AccountRecoveryKey, _> = "not an encapsulated key".parse();

        assert!(matches!(result, Err(AccountRecoveryKeyError::Malformed)));
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
            AccountRecoveryKey::encapsulate(member_user_key, &other_public_key, &ctx).unwrap();

        let result =
            account_recovery_key.decapsulate_member_user_key(&organization_private_key, &mut ctx);

        assert!(matches!(
            result,
            Err(AccountRecoveryKeyError::DecapsulationFailed)
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
