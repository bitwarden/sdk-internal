//! Account recovery: a member's user key, held by the organization so that admins can recover the
//! member's account by resetting the member's master password.
//!
//! The server and the API name this value the "reset password key" (`resetPasswordKey`).
//!
//! # Versions
//!
//! - V1: the member's user key encapsulated to the organization's public key. Nothing authenticates
//!   the sender.
//! - V2 (planned): the member's user key sealed from the member's identity to the organization's
//!   identity in an identity-sealed key envelope, which authenticates the member as the sender.
//!
//! [`AccountRecovery::make`] takes the [`TrustProof`] for the organization's public key. Some V1
//! flows have no way to verify the public key, and use [`AccountRecovery::make_untrusted`]. V2
//! has no untrusted variant.
//!
//! A V1 to V2 upgrade of the member's user key leaves the account recovery of the V1 user key in
//! place. An admin replaces it with [`AccountRecovery::make_after_v2_upgrade`].
//!
//! Until identities exist, [`PublicKey`] and [`OrganizationPrivateKey`] stand in for the
//! organization's identity.

use std::str::FromStr;

use bitwarden_crypto::{
    KeyId, KeySlotIds, KeyStoreContext, PublicKey, SymmetricKeyAlgorithm, UnsignedSharedKey,
};
use thiserror::Error;

use crate::{
    organization_private_key::OrganizationPrivateKey,
    trust_proof::{TrustProof, TrustProofError},
};

/// Errors that can occur when parsing an account recovery.
#[derive(Debug, Error)]
pub enum AccountRecoveryParseError {
    /// The value stored for the member is not in a known account recovery format.
    #[error("The account recovery key is malformed")]
    Malformed,
}

/// Errors that can occur when making an account recovery after a V1 to V2 upgrade of the member's
/// user key.
#[derive(Debug, Error, PartialEq)]
pub enum AccountRecoveryMakeAfterV2UpgradeError {
    /// The member's user key is not in the key store context.
    #[error("The member's user key does not exist in the key store context")]
    MissingMemberUserKey,
    /// The member's user key is not a V2 user key.
    #[error("The member's user key is not a V2 user key")]
    MemberUserKeyNotV2,
    /// The member's user key has a key id other than the expected one.
    #[error("The member's user key id does not match the expected key id")]
    UserKeyIdMismatch,
    /// The account recovery could not be made with the organization's trust proof.
    #[error(transparent)]
    Make(#[from] AccountRecoveryMakeError),
}

/// Errors that can occur when making an account recovery with a trust proof.
#[derive(Debug, Error, PartialEq)]
pub enum AccountRecoveryMakeError {
    /// The private key of
    /// [`CryptographicProof::OwnPrivateKey`](crate::trust_proof::CryptographicProof::OwnPrivateKey)
    /// is not in the key store context.
    #[error("The private key of the trust proof is not in the key store context")]
    PrivateKeyNotInContext,
    /// The member's user key is not in the key store context.
    #[error("The member's user key could not be encapsulated to the organization's public key")]
    EncapsulationFailed,
    /// The public key did not pass the trust proof.
    #[error("The organization's public key could not be trusted")]
    UntrustedPublicKey,
}

impl From<TrustProofError> for AccountRecoveryMakeError {
    fn from(error: TrustProofError) -> Self {
        match error {
            TrustProofError::PrivateKeyNotInContext => Self::PrivateKeyNotInContext,
            TrustProofError::UntrustedPublicKey => Self::UntrustedPublicKey,
        }
    }
}

/// Errors that can occur when making an account recovery without a trust proof.
#[derive(Debug, Error)]
pub enum AccountRecoveryMakeUntrustedError {
    /// The member's user key is not in the key store context.
    #[error("The member's user key could not be encapsulated to the organization's public key")]
    EncapsulationFailed,
}

/// Errors that can occur when unsealing an account recovery.
#[derive(Debug, Error)]
pub enum AccountRecoveryUnsealError {
    /// The account recovery was made for a different organization key pair, or the stored value is
    /// corrupt. V1 cannot tell these apart.
    #[error(
        "The account recovery key could not be decapsulated with the organization's private key"
    )]
    DecapsulationFailed,
}

/// A member's user key, held by the organization so that admins can recover the account.
pub enum AccountRecovery {
    /// The member's user key encapsulated to the organization's public key.
    ///
    /// Encapsulation does not authenticate the sender. A swapped public key hands the member's user
    /// key to whoever holds the matching private key.
    V1(UnsignedSharedKey),
}

impl AccountRecovery {
    /// Makes an account recovery of the member's user key, after the organization's public key
    /// passes `trust_proof`.
    pub fn make<Ids: KeySlotIds>(
        member_user_key: Ids::Symmetric,
        organization_public_key: &PublicKey,
        trust_proof: &TrustProof<Ids>,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, AccountRecoveryMakeError> {
        trust_proof.verify(organization_public_key, ctx)?;

        let encapsulated_key =
            UnsignedSharedKey::encapsulate(member_user_key, organization_public_key, ctx)
                .map_err(|_| AccountRecoveryMakeError::EncapsulationFailed)?;

        Ok(Self::V1(encapsulated_key))
    }

    /// Makes an account recovery of the member's V2 user key, after a V1 to V2 upgrade of that key.
    ///
    /// The server reports `expected_user_key_id` and can name any key, so the key id of
    /// `v2_user_key` must match it. The organization's private key is the trust proof for
    /// `organization_public_key`.
    pub fn make_after_v2_upgrade<Ids: KeySlotIds>(
        v2_user_key: Ids::Symmetric,
        expected_user_key_id: KeyId,
        organization_private_key: &OrganizationPrivateKey<Ids>,
        organization_public_key: &PublicKey,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, AccountRecoveryMakeAfterV2UpgradeError> {
        if !ctx.has_symmetric_key(v2_user_key) {
            return Err(AccountRecoveryMakeAfterV2UpgradeError::MissingMemberUserKey);
        }
        if !matches!(
            ctx.get_symmetric_key_algorithm(v2_user_key),
            Ok(SymmetricKeyAlgorithm::XAes256Gcm)
        ) {
            return Err(AccountRecoveryMakeAfterV2UpgradeError::MemberUserKeyNotV2);
        }
        if ctx.get_symmetric_key_id(v2_user_key) != Some(expected_user_key_id) {
            return Err(AccountRecoveryMakeAfterV2UpgradeError::UserKeyIdMismatch);
        }

        Ok(Self::make(
            v2_user_key,
            organization_public_key,
            &organization_private_key.trust_proof(),
            ctx,
        )?)
    }

    /// Makes a V1 account recovery of the member's user key, without verifying the
    /// organization's public key.
    ///
    /// Only for V1 flows that have no way to verify the public key. A swapped public key hands the
    /// member's user key to whoever holds the matching private key.
    pub fn make_untrusted<Ids: KeySlotIds>(
        member_user_key: Ids::Symmetric,
        organization_public_key: &PublicKey,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, AccountRecoveryMakeUntrustedError> {
        let encapsulated_key =
            UnsignedSharedKey::encapsulate(member_user_key, organization_public_key, ctx)
                .map_err(|_| AccountRecoveryMakeUntrustedError::EncapsulationFailed)?;

        Ok(Self::V1(encapsulated_key))
    }

    /// Opens the member's user key, returning the id it was added to the context under.
    pub fn unseal_member_user_key<Ids: KeySlotIds>(
        &self,
        organization_private_key: &OrganizationPrivateKey<Ids>,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Symmetric, AccountRecoveryUnsealError> {
        let Self::V1(encapsulated_key) = self;

        organization_private_key
            .decapsulate_key(encapsulated_key, ctx)
            .map_err(|_| AccountRecoveryUnsealError::DecapsulationFailed)
    }
}

impl FromStr for AccountRecovery {
    type Err = AccountRecoveryParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .parse()
            .map(Self::V1)
            .map_err(|_| AccountRecoveryParseError::Malformed)
    }
}

impl From<&AccountRecovery> for String {
    fn from(value: &AccountRecovery) -> Self {
        let AccountRecovery::V1(encapsulated_key) = value;

        encapsulated_key.to_string()
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{
        KeyStore, PublicKeyEncryptionAlgorithm,
        SymmetricKeyAlgorithm::{Aes256CbcHmac, XAes256Gcm},
    };

    use super::*;
    use crate::test_support::{
        TEST_VECTOR_V1_MEMBER_USER_KEY, TestIds, add_symmetric_key,
        unwrap_v1_organization_private_key,
    };

    /// [`TEST_VECTOR_V1_MEMBER_USER_KEY`] encapsulated to the pinned organization public key.
    const TEST_VECTOR_ACCOUNT_RECOVERY: &str = "4.GMFvOS56Osw1wUBwRx+lL6/wmiRxLZ+6/jWuDwMVCL1LoHKPn71uI+I5bofMog7AUFOZfnHYvkY7DezYDVj635x8DrD3msVrpHDis2WX9KDV3mffFVQ8SItiIJI4iD2x98uDYCDClMqI5CzFI/IroOYUDxleS3VVOncjUY2AlFSPXsfBClrC1nLsP6dkseh8kI27ZznWYdb2bxq+6a9nBuXz0ykiwrYJy+DIgCNqjpZhWOB8L+2LFGNfVR+Xz3DNDgmfo+t5ufdu9Y5HcKDOfFpkDOy7lngBtQjLBSaQcX3sh7lRxgDzAGzzcNQ+aTsak8YAf+e+lrWwhva7RxTaeA==";

    #[test]
    fn test_account_recovery_unseals_to_the_member_user_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_private_key = unwrap_v1_organization_private_key(&mut ctx);
        let member_user_key = ctx.make_symmetric_key(Aes256CbcHmac);

        let account_recovery = AccountRecovery::make(
            member_user_key,
            &organization_private_key.public_key(&ctx).unwrap(),
            &TrustProof::TestStub(Ok(())),
            &ctx,
        )
        .unwrap();
        let unsealed = account_recovery
            .unseal_member_user_key(&organization_private_key, &mut ctx)
            .unwrap();

        ctx.assert_symmetric_keys_equal(member_user_key, unsealed);
    }

    #[test]
    fn test_untrusted_account_recovery_unseals_to_the_member_user_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_private_key = unwrap_v1_organization_private_key(&mut ctx);
        let member_user_key = ctx.make_symmetric_key(Aes256CbcHmac);

        let account_recovery = AccountRecovery::make_untrusted(
            member_user_key,
            &organization_private_key.public_key(&ctx).unwrap(),
            &ctx,
        )
        .unwrap();
        let unsealed = account_recovery
            .unseal_member_user_key(&organization_private_key, &mut ctx)
            .unwrap();

        ctx.assert_symmetric_keys_equal(member_user_key, unsealed);
    }

    #[test]
    fn test_account_recovery_survives_a_string_round_trip() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_private_key = unwrap_v1_organization_private_key(&mut ctx);
        let member_user_key = ctx.make_symmetric_key(Aes256CbcHmac);
        let account_recovery = AccountRecovery::make(
            member_user_key,
            &organization_private_key.public_key(&ctx).unwrap(),
            &TrustProof::TestStub(Ok(())),
            &ctx,
        )
        .unwrap();

        let parsed: AccountRecovery = String::from(&account_recovery).parse().unwrap();

        let unsealed = parsed
            .unseal_member_user_key(&organization_private_key, &mut ctx)
            .unwrap();
        ctx.assert_symmetric_keys_equal(member_user_key, unsealed);
    }

    #[test]
    fn test_parsing_a_key_in_no_known_format_fails() {
        let result: Result<AccountRecovery, _> = "not an encapsulated key".parse();

        assert!(matches!(result, Err(AccountRecoveryParseError::Malformed)));
    }

    #[test]
    fn test_making_with_a_failed_trust_proof_fails_with_the_matching_error() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_private_key = unwrap_v1_organization_private_key(&mut ctx);
        let organization_public_key = organization_private_key.public_key(&ctx).unwrap();
        let member_user_key = ctx.make_symmetric_key(Aes256CbcHmac);

        for (trust_proof_error, expected_error) in [
            (
                TrustProofError::PrivateKeyNotInContext,
                AccountRecoveryMakeError::PrivateKeyNotInContext,
            ),
            (
                TrustProofError::UntrustedPublicKey,
                AccountRecoveryMakeError::UntrustedPublicKey,
            ),
        ] {
            let result = AccountRecovery::make(
                member_user_key,
                &organization_public_key,
                &TrustProof::TestStub(Err(trust_proof_error)),
                &ctx,
            );

            assert_eq!(result.err(), Some(expected_error));
        }
    }

    #[test]
    fn test_making_with_a_missing_member_user_key_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_private_key = unwrap_v1_organization_private_key(&mut ctx);
        let other_key_store = KeyStore::<TestIds>::default();
        let mut other_ctx = other_key_store.context_mut();
        let missing_member_user_key = other_ctx.make_symmetric_key(Aes256CbcHmac);

        let result = AccountRecovery::make(
            missing_member_user_key,
            &organization_private_key.public_key(&ctx).unwrap(),
            &TrustProof::TestStub(Ok(())),
            &ctx,
        );

        assert!(matches!(
            result,
            Err(AccountRecoveryMakeError::EncapsulationFailed)
        ));
    }

    #[test]
    fn test_making_untrusted_with_a_missing_member_user_key_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_private_key = unwrap_v1_organization_private_key(&mut ctx);
        let organization_public_key = organization_private_key.public_key(&ctx).unwrap();
        let other_key_store = KeyStore::<TestIds>::default();
        let mut other_ctx = other_key_store.context_mut();
        let missing_member_user_key = other_ctx.make_symmetric_key(Aes256CbcHmac);

        let result = AccountRecovery::make_untrusted(
            missing_member_user_key,
            &organization_public_key,
            &ctx,
        );

        assert!(matches!(
            result,
            Err(AccountRecoveryMakeUntrustedError::EncapsulationFailed)
        ));
    }

    #[test]
    fn test_account_recovery_made_after_v2_upgrade_unseals_to_the_v2_user_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_private_key = unwrap_v1_organization_private_key(&mut ctx);
        let v2_user_key = ctx.make_symmetric_key(XAes256Gcm);
        let v2_user_key_id = ctx.get_symmetric_key_id(v2_user_key).unwrap();

        let account_recovery = AccountRecovery::make_after_v2_upgrade(
            v2_user_key,
            v2_user_key_id,
            &organization_private_key,
            &organization_private_key.public_key(&ctx).unwrap(),
            &ctx,
        )
        .unwrap();
        let unsealed = account_recovery
            .unseal_member_user_key(&organization_private_key, &mut ctx)
            .unwrap();

        ctx.assert_symmetric_keys_equal(v2_user_key, unsealed);
    }

    #[test]
    fn test_making_after_v2_upgrade_with_a_missing_member_user_key_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_private_key = unwrap_v1_organization_private_key(&mut ctx);
        let other_key_store = KeyStore::<TestIds>::default();
        let mut other_ctx = other_key_store.context_mut();
        let missing_v2_user_key = other_ctx.make_symmetric_key(XAes256Gcm);
        let missing_v2_user_key_id = other_ctx.get_symmetric_key_id(missing_v2_user_key).unwrap();

        let result = AccountRecovery::make_after_v2_upgrade(
            missing_v2_user_key,
            missing_v2_user_key_id,
            &organization_private_key,
            &organization_private_key.public_key(&ctx).unwrap(),
            &ctx,
        );

        assert_eq!(
            result.err(),
            Some(AccountRecoveryMakeAfterV2UpgradeError::MissingMemberUserKey)
        );
    }

    #[test]
    fn test_making_after_v2_upgrade_with_a_v1_user_key_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_private_key = unwrap_v1_organization_private_key(&mut ctx);
        let v1_user_key = ctx.make_symmetric_key(Aes256CbcHmac);
        let v2_user_key = ctx.make_symmetric_key(XAes256Gcm);
        let v2_user_key_id = ctx.get_symmetric_key_id(v2_user_key).unwrap();

        let result = AccountRecovery::make_after_v2_upgrade(
            v1_user_key,
            v2_user_key_id,
            &organization_private_key,
            &organization_private_key.public_key(&ctx).unwrap(),
            &ctx,
        );

        assert_eq!(
            result.err(),
            Some(AccountRecoveryMakeAfterV2UpgradeError::MemberUserKeyNotV2)
        );
    }

    #[test]
    fn test_making_after_v2_upgrade_with_the_key_id_of_another_key_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_private_key = unwrap_v1_organization_private_key(&mut ctx);
        let v2_user_key = ctx.make_symmetric_key(XAes256Gcm);
        let other_v2_user_key = ctx.make_symmetric_key(XAes256Gcm);
        let other_v2_user_key_id = ctx.get_symmetric_key_id(other_v2_user_key).unwrap();

        let result = AccountRecovery::make_after_v2_upgrade(
            v2_user_key,
            other_v2_user_key_id,
            &organization_private_key,
            &organization_private_key.public_key(&ctx).unwrap(),
            &ctx,
        );

        assert_eq!(
            result.err(),
            Some(AccountRecoveryMakeAfterV2UpgradeError::UserKeyIdMismatch)
        );
    }

    #[test]
    fn test_making_after_v2_upgrade_with_the_public_key_of_another_organization_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_private_key = unwrap_v1_organization_private_key(&mut ctx);
        let other_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let other_public_key = ctx.get_public_key(other_private_key).unwrap();
        let v2_user_key = ctx.make_symmetric_key(XAes256Gcm);
        let v2_user_key_id = ctx.get_symmetric_key_id(v2_user_key).unwrap();

        let result = AccountRecovery::make_after_v2_upgrade(
            v2_user_key,
            v2_user_key_id,
            &organization_private_key,
            &other_public_key,
            &ctx,
        );

        assert_eq!(
            result.err(),
            Some(AccountRecoveryMakeAfterV2UpgradeError::Make(
                AccountRecoveryMakeError::OwnPublicKeyMismatch
            ))
        );
    }

    #[test]
    fn test_unsealing_an_account_recovery_for_another_organization_fails() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_private_key = unwrap_v1_organization_private_key(&mut ctx);
        let other_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let other_public_key = ctx.get_public_key(other_private_key).unwrap();
        let member_user_key = ctx.make_symmetric_key(Aes256CbcHmac);
        let account_recovery =
            AccountRecovery::make_untrusted(member_user_key, &other_public_key, &ctx).unwrap();

        let result = account_recovery.unseal_member_user_key(&organization_private_key, &mut ctx);

        assert!(matches!(
            result,
            Err(AccountRecoveryUnsealError::DecapsulationFailed)
        ));
    }

    #[test]
    #[ignore = "Manual test to generate test vectors"]
    fn generate_test_vectors() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_private_key = unwrap_v1_organization_private_key(&mut ctx);
        let member_user_key = add_symmetric_key(TEST_VECTOR_V1_MEMBER_USER_KEY, &mut ctx);

        let account_recovery = AccountRecovery::make_untrusted(
            member_user_key,
            &organization_private_key.public_key(&ctx).unwrap(),
            &ctx,
        )
        .unwrap();

        println!(
            "const TEST_VECTOR_ACCOUNT_RECOVERY: &str = \"{}\";",
            String::from(&account_recovery)
        );
    }

    #[test]
    fn test_account_recovery_test_vector() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let organization_private_key = unwrap_v1_organization_private_key(&mut ctx);
        let member_user_key = add_symmetric_key(TEST_VECTOR_V1_MEMBER_USER_KEY, &mut ctx);

        let account_recovery: AccountRecovery = TEST_VECTOR_ACCOUNT_RECOVERY.parse().unwrap();
        let unsealed = account_recovery
            .unseal_member_user_key(&organization_private_key, &mut ctx)
            .unwrap();

        ctx.assert_symmetric_keys_equal(member_user_key, unsealed);
    }
}
