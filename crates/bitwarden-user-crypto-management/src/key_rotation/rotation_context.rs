use bitwarden_core::key_management::{KeySlotIds, SymmetricKeySlotId};
use bitwarden_crypto::{KeyStore, KeyStoreContext, PublicKey, SymmetricKeyAlgorithm};
use tracing::{debug, info, warn};

use super::{
    RotateUserKeysError,
    rotate_user_keys::UpgradeTokenAction,
    sync::SyncedAccountData,
    unlock::{V1EmergencyAccessMembership, V1OrganizationMembership},
};

#[derive(Debug)]
struct UntrustedKeyError;

/// Whether the rotation creates a V2 upgrade token.
///
/// A token only makes sense when the user moves from a V1 to a V2 user key. Every other rotation
/// logs the user out of their other sessions. The SDK always rotates into a V2 user key, so the
/// current user key decides the answer.
fn creates_v2_upgrade_token(
    current_user_key_id: SymmetricKeySlotId,
    upgrade_token_action: UpgradeTokenAction,
    ctx: &KeyStoreContext<KeySlotIds>,
) -> bool {
    if matches!(upgrade_token_action, UpgradeTokenAction::Skip) {
        debug!("UpgradeTokenAction::Skip, no upgrade token is created for this rotation");
        return false;
    }

    ctx.is_v1_symmetric_key(current_user_key_id)
        .unwrap_or(false)
}

/// The organization memberships the user has to confirm as trusted before the rotation.
///
/// When the rotation creates a V2 upgrade token, returns no memberships. Organization admins update
/// account recovery from that token, so the user confirms nothing. Every other rotation returns the
/// memberships it was given.
pub(super) fn organization_memberships_needing_trust(
    organization_memberships: Vec<V1OrganizationMembership>,
    upgrade_token_action: UpgradeTokenAction,
    key_store: &KeyStore<KeySlotIds>,
) -> Vec<V1OrganizationMembership> {
    let creates_v2_upgrade_token = {
        let ctx = key_store.context();
        creates_v2_upgrade_token(SymmetricKeySlotId::User, upgrade_token_action, &ctx)
    };

    if creates_v2_upgrade_token {
        info!(
            "Rotation creates a V2 upgrade token, none of the {} organization public key(s) need confirmation",
            organization_memberships.len()
        );
        return vec![];
    }

    organization_memberships
}

fn filter_trusted_organization(
    org: &[V1OrganizationMembership],
    trusted_orgs: &[PublicKey],
) -> Result<Vec<V1OrganizationMembership>, UntrustedKeyError> {
    org.iter()
        .map(|o| {
            let is_trusted = trusted_orgs.iter().any(|tk| tk == &o.public_key);
            if !is_trusted {
                warn!(
                    "Aborting because untrusted organization detected with id={}",
                    o.organization_id
                );
                Err(UntrustedKeyError)
            } else {
                Ok(o.clone())
            }
        })
        .collect::<Result<Vec<V1OrganizationMembership>, UntrustedKeyError>>()
}

fn filter_trusted_emergency_access(
    ea: &[V1EmergencyAccessMembership],
    trusted_emergency_access_user_public_keys: &[PublicKey],
) -> Result<Vec<V1EmergencyAccessMembership>, UntrustedKeyError> {
    ea.iter()
        .map(|e| {
            let is_trusted = trusted_emergency_access_user_public_keys
                .iter()
                .any(|tk| tk == &e.public_key);
            if !is_trusted {
                warn!(
                    "Aborting because untrusted emergency access membership detected with id={}",
                    e.id
                );
                Err(UntrustedKeyError)
            } else {
                Ok(e.to_owned())
            }
        })
        .collect::<Result<Vec<V1EmergencyAccessMembership>, UntrustedKeyError>>()
}

pub(super) struct RotationContext {
    pub(super) v1_organization_memberships: Vec<V1OrganizationMembership>,
    pub(super) v1_emergency_access_memberships: Vec<V1EmergencyAccessMembership>,
    pub(super) current_user_key_id: SymmetricKeySlotId,
    pub(super) new_user_key_id: SymmetricKeySlotId,
    pub(super) creates_v2_upgrade_token: bool,
}

/// Generates the new user key and collects the memberships that get a copy of it.
///
/// Returns [`RotateUserKeysError::UntrustedKey`] if the rotation needs a public key the user has
/// not confirmed. A public key does not show who owns it, so the user has to confirm it first.
pub(super) fn make_rotation_context(
    sync: &SyncedAccountData,
    trusted_organization_public_keys: &[PublicKey],
    trusted_emergency_access_public_keys: &[PublicKey],
    upgrade_token_action: UpgradeTokenAction,
    ctx: &mut KeyStoreContext<KeySlotIds>,
) -> Result<RotationContext, RotateUserKeysError> {
    info!(
        "Existing user cryptographic version {:?}",
        sync.wrapped_account_cryptographic_state
    );
    let current_user_key_id = SymmetricKeySlotId::User;

    debug!("Generating new XAES-256-GCM user key for key rotation");
    let new_user_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

    let creates_v2_upgrade_token =
        creates_v2_upgrade_token(current_user_key_id, upgrade_token_action, ctx);

    let v1_organization_memberships = if creates_v2_upgrade_token {
        // Organization admins update account recovery from the token. The user is never asked to
        // trust these keys.
        info!(
            "Skipping the trust check for {} organization public key(s), the rotation does not use them",
            sync.organization_memberships.len()
        );
        sync.organization_memberships.clone()
    } else {
        filter_trusted_organization(
            sync.organization_memberships.as_slice(),
            trusted_organization_public_keys,
        )
        .map_err(|_| RotateUserKeysError::UntrustedKey)?
    };

    let v1_emergency_access_memberships = filter_trusted_emergency_access(
        sync.emergency_access_memberships.as_slice(),
        trusted_emergency_access_public_keys,
    )
    .map_err(|_| RotateUserKeysError::UntrustedKey)?;

    Ok(RotationContext {
        v1_organization_memberships,
        v1_emergency_access_memberships,
        current_user_key_id,
        new_user_key_id,
        creates_v2_upgrade_token,
    })
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::{
        KeySlotIds, PrivateKeySlotId, SymmetricKeySlotId,
        account_cryptographic_state::WrappedAccountCryptographicState,
    };
    use bitwarden_crypto::{
        KeyStore, KeyStoreContext, PublicKeyEncryptionAlgorithm, SymmetricKeyAlgorithm,
    };
    use uuid::Uuid;

    use super::{
        super::{
            sync::SyncedAccountData,
            unlock::{V1EmergencyAccessMembership, V1OrganizationMembership},
        },
        RotateUserKeysError, UpgradeTokenAction, creates_v2_upgrade_token,
        filter_trusted_emergency_access, filter_trusted_organization, make_rotation_context,
        organization_memberships_needing_trust,
    };

    #[test]
    fn test_creates_v2_upgrade_token_v1_user_key_with_create_if_needed() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        let current_user_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

        assert!(creates_v2_upgrade_token(
            current_user_key_id,
            UpgradeTokenAction::CreateIfNeeded,
            &ctx,
        ));
    }

    #[test]
    fn test_creates_v2_upgrade_token_v1_user_key_with_skip() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        let current_user_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

        assert!(!creates_v2_upgrade_token(
            current_user_key_id,
            UpgradeTokenAction::Skip,
            &ctx,
        ));
    }

    #[test]
    fn test_creates_v2_upgrade_token_v2_user_key_with_create_if_needed() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();

        let current_user_key_id = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

        assert!(!creates_v2_upgrade_token(
            current_user_key_id,
            UpgradeTokenAction::CreateIfNeeded,
            &ctx,
        ));
    }

    #[test]
    fn test_creates_v2_upgrade_token_missing_current_user_key() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let ctx = store.context();

        assert!(
            !creates_v2_upgrade_token(
                SymmetricKeySlotId::User,
                UpgradeTokenAction::CreateIfNeeded,
                &ctx,
            ),
            "a user key that cannot be read must not be treated as V1"
        );
    }

    fn make_org_membership(
        ctx: &mut KeyStoreContext<KeySlotIds>,
    ) -> (V1OrganizationMembership, PrivateKeySlotId) {
        let org_private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        (
            V1OrganizationMembership {
                organization_id: Uuid::new_v4(),
                name: "Test Org".to_string(),
                public_key: ctx.get_public_key(org_private_key).expect("key exists"),
            },
            org_private_key,
        )
    }

    fn make_ea_membership(
        ctx: &mut KeyStoreContext<KeySlotIds>,
    ) -> (V1EmergencyAccessMembership, PrivateKeySlotId) {
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        (
            V1EmergencyAccessMembership {
                id: Uuid::new_v4(),
                name: "Test User".to_string(),
                public_key: ctx.get_public_key(private_key).expect("key exists"),
                grantee_id: Uuid::new_v4(),
            },
            private_key,
        )
    }

    fn assert_org_membership_eq(
        actual: &V1OrganizationMembership,
        expected: &V1OrganizationMembership,
    ) {
        assert_eq!(actual.organization_id, expected.organization_id);
        assert_eq!(actual.name, expected.name);
        assert_eq!(actual.public_key, expected.public_key);
    }

    fn assert_ea_membership_eq(
        actual: &V1EmergencyAccessMembership,
        expected: &V1EmergencyAccessMembership,
    ) {
        assert_eq!(actual.id, expected.id);
        assert_eq!(actual.name, expected.name);
        assert_eq!(actual.grantee_id, expected.grantee_id);
        assert_eq!(actual.public_key, expected.public_key);
    }

    fn make_test_sync(
        org_memberships: Vec<V1OrganizationMembership>,
        ea_memberships: Vec<V1EmergencyAccessMembership>,
        ctx: &mut KeyStoreContext<KeySlotIds>,
    ) -> SyncedAccountData {
        let user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let private_key = ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1);
        let wrapped_private_key = ctx.wrap_private_key(user_key, private_key).unwrap();
        SyncedAccountData {
            wrapped_account_cryptographic_state: WrappedAccountCryptographicState::V1 {
                private_key: wrapped_private_key,
            },
            folders: vec![],
            ciphers: vec![],
            sends: vec![],
            emergency_access_memberships: ea_memberships,
            organization_memberships: org_memberships,
            trusted_devices: vec![],
            passkeys: vec![],
            kdf_and_salt: None,
        }
    }

    #[test]
    fn test_filter_trusted_org_empty_list() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (org, _) = make_org_membership(&mut ctx);
        let trusted = [org.public_key.clone()];

        // Note this is important to allow for the case where a user has no org memberships, but has
        // provided a non-empty list of trusted org public keys. For example their
        // organization membership was removed in the middle of the key rotation process.
        let result = filter_trusted_organization(&[], &trusted);

        assert!(matches!(result, Ok(ref v) if v.is_empty()));
    }

    #[test]
    fn test_filter_trusted_org_all_trusted() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (org1, _) = make_org_membership(&mut ctx);
        let (org2, _) = make_org_membership(&mut ctx);
        let trusted = [org1.public_key.clone(), org2.public_key.clone()];
        let expected_org1 = org1.clone();
        let expected_org2 = org2.clone();

        let result = filter_trusted_organization(&[org1, org2], &trusted);

        let memberships = result.unwrap();
        assert_eq!(memberships.len(), 2);
        assert_org_membership_eq(&memberships[0], &expected_org1);
        assert_org_membership_eq(&memberships[1], &expected_org2);
    }

    #[test]
    fn test_filter_trusted_org_one_untrusted() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (org1, _) = make_org_membership(&mut ctx);
        let (org2, _) = make_org_membership(&mut ctx);
        let trusted = [org1.public_key.clone()];

        let result = filter_trusted_organization(&[org1, org2], &trusted);

        assert!(result.is_err());
    }

    #[test]
    fn test_filter_trusted_org_empty_trusted_with_orgs() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (org, _) = make_org_membership(&mut ctx);

        let result = filter_trusted_organization(&[org], &[]);

        assert!(result.is_err());
    }

    #[test]
    fn test_filter_trusted_ea_empty_list() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (ea, _) = make_ea_membership(&mut ctx);
        let trusted = [ea.public_key.clone()];

        let result = filter_trusted_emergency_access(&[], &trusted);

        assert!(matches!(result, Ok(ref v) if v.is_empty()));
    }

    #[test]
    fn test_filter_trusted_ea_all_trusted() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (ea1, _) = make_ea_membership(&mut ctx);
        let (ea2, _) = make_ea_membership(&mut ctx);
        let trusted = [ea1.public_key.clone(), ea2.public_key.clone()];
        let expected_ea1 = ea1.clone();
        let expected_ea2 = ea2.clone();

        let result = filter_trusted_emergency_access(&[ea1, ea2], &trusted);

        let memberships = result.expect("should succeed");
        assert_eq!(memberships.len(), 2);
        assert_ea_membership_eq(&memberships[0], &expected_ea1);
        assert_ea_membership_eq(&memberships[1], &expected_ea2);
    }

    #[test]
    fn test_filter_trusted_ea_one_untrusted() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (ea1, _) = make_ea_membership(&mut ctx);
        let (ea2, _) = make_ea_membership(&mut ctx);
        // only ea1 is trusted
        let trusted = [ea1.public_key.clone()];

        let result = filter_trusted_emergency_access(&[ea1, ea2], &trusted);

        assert!(result.is_err());
    }

    #[test]
    fn test_filter_trusted_ea_empty_trusted_with_memberships() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (ea, _) = make_ea_membership(&mut ctx);

        let result = filter_trusted_emergency_access(&[ea], &[]);

        assert!(result.is_err());
    }

    #[test]
    fn test_make_rotation_context_empty_data() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let sync = make_test_sync(vec![], vec![], &mut ctx);

        let result = make_rotation_context(&sync, &[], &[], UpgradeTokenAction::Skip, &mut ctx);

        let rotation_ctx = result.expect("should succeed");
        assert!(rotation_ctx.v1_organization_memberships.is_empty());
        assert!(rotation_ctx.v1_emergency_access_memberships.is_empty());
        assert_eq!(rotation_ctx.current_user_key_id, SymmetricKeySlotId::User);
        assert_ne!(
            rotation_ctx.new_user_key_id,
            rotation_ctx.current_user_key_id
        );
        assert!(!rotation_ctx.creates_v2_upgrade_token);
    }

    #[test]
    fn test_make_rotation_context_untrusted_org_with_upgrade_token_is_accepted() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        ctx.persist_symmetric_key(user_key, SymmetricKeySlotId::User)
            .expect("persisting the user key should work");
        let (org, _) = make_org_membership(&mut ctx);
        let expected_org = org.clone();
        let sync = make_test_sync(vec![org], vec![], &mut ctx);

        let result = make_rotation_context(
            &sync,
            &[],
            &[],
            UpgradeTokenAction::CreateIfNeeded,
            &mut ctx,
        );

        let rotation_ctx = result.expect("should succeed");
        assert!(rotation_ctx.creates_v2_upgrade_token);
        assert_eq!(rotation_ctx.v1_organization_memberships.len(), 1);
        assert_org_membership_eq(&rotation_ctx.v1_organization_memberships[0], &expected_org);
    }

    #[test]
    fn test_make_rotation_context_untrusted_org_v2_user_returns_error() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        ctx.persist_symmetric_key(user_key, SymmetricKeySlotId::User)
            .expect("persisting the user key should work");
        let (org, _) = make_org_membership(&mut ctx);
        let sync = make_test_sync(vec![org], vec![], &mut ctx);

        let result = make_rotation_context(
            &sync,
            &[],
            &[],
            UpgradeTokenAction::CreateIfNeeded,
            &mut ctx,
        );

        assert!(matches!(result, Err(RotateUserKeysError::UntrustedKey)));
    }

    #[test]
    fn test_make_rotation_context_untrusted_emergency_access_with_upgrade_token_returns_error() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let user_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        ctx.persist_symmetric_key(user_key, SymmetricKeySlotId::User)
            .expect("persisting the user key should work");
        let (ea, _) = make_ea_membership(&mut ctx);
        let sync = make_test_sync(vec![], vec![ea], &mut ctx);

        let result = make_rotation_context(
            &sync,
            &[],
            &[],
            UpgradeTokenAction::CreateIfNeeded,
            &mut ctx,
        );

        assert!(matches!(result, Err(RotateUserKeysError::UntrustedKey)));
    }

    #[test]
    fn test_make_rotation_context_trusted_org_and_ea() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (org, _) = make_org_membership(&mut ctx);
        let (ea, _) = make_ea_membership(&mut ctx);
        let trusted_orgs = [org.public_key.clone()];
        let trusted_eas = [ea.public_key.clone()];
        let expected_org = org.clone();
        let expected_ea = ea.clone();
        let sync = make_test_sync(vec![org], vec![ea], &mut ctx);

        let result = make_rotation_context(
            &sync,
            &trusted_orgs,
            &trusted_eas,
            UpgradeTokenAction::Skip,
            &mut ctx,
        );

        let rotation_ctx = result.expect("should succeed");
        assert_eq!(rotation_ctx.v1_organization_memberships.len(), 1);
        assert_org_membership_eq(&rotation_ctx.v1_organization_memberships[0], &expected_org);
        assert_eq!(rotation_ctx.v1_emergency_access_memberships.len(), 1);
        assert_ea_membership_eq(
            &rotation_ctx.v1_emergency_access_memberships[0],
            &expected_ea,
        );
        assert_eq!(rotation_ctx.current_user_key_id, SymmetricKeySlotId::User);
        assert_ne!(
            rotation_ctx.new_user_key_id,
            rotation_ctx.current_user_key_id
        );
    }

    #[test]
    fn test_make_rotation_context_untrusted_org_returns_error() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (org, _) = make_org_membership(&mut ctx);
        let sync = make_test_sync(vec![org], vec![], &mut ctx);

        let result = make_rotation_context(&sync, &[], &[], UpgradeTokenAction::Skip, &mut ctx);

        assert!(matches!(result, Err(RotateUserKeysError::UntrustedKey)));
    }

    #[test]
    fn test_make_rotation_context_untrusted_ea_returns_error() {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (ea, _) = make_ea_membership(&mut ctx);
        let sync = make_test_sync(vec![], vec![ea], &mut ctx);

        let result = make_rotation_context(&sync, &[], &[], UpgradeTokenAction::Skip, &mut ctx);

        assert!(matches!(result, Err(RotateUserKeysError::UntrustedKey)));
    }

    /// Persists a user key of the given algorithm and returns one organization membership.
    fn make_store_with_user_key(
        algorithm: SymmetricKeyAlgorithm,
    ) -> (KeyStore<KeySlotIds>, V1OrganizationMembership) {
        let store: KeyStore<KeySlotIds> = KeyStore::default();
        let org = {
            let mut ctx = store.context_mut();
            let user_key = ctx.make_symmetric_key(algorithm);
            ctx.persist_symmetric_key(user_key, SymmetricKeySlotId::User)
                .expect("persisting the user key should work");
            make_org_membership(&mut ctx).0
        };

        (store, org)
    }

    #[test]
    fn test_organization_memberships_needing_trust_v1_user_key_with_create_if_needed_is_empty() {
        let (store, org) = make_store_with_user_key(SymmetricKeyAlgorithm::Aes256CbcHmac);

        let memberships = organization_memberships_needing_trust(
            vec![org],
            UpgradeTokenAction::CreateIfNeeded,
            &store,
        );

        assert!(memberships.is_empty());
    }

    #[test]
    fn test_organization_memberships_needing_trust_v1_user_key_with_skip() {
        let (store, org) = make_store_with_user_key(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let expected_org = org.clone();

        let memberships =
            organization_memberships_needing_trust(vec![org], UpgradeTokenAction::Skip, &store);

        assert_eq!(memberships.len(), 1);
        assert_org_membership_eq(&memberships[0], &expected_org);
    }

    #[test]
    fn test_organization_memberships_needing_trust_v2_user_key_with_create_if_needed() {
        let (store, org) = make_store_with_user_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let expected_org = org.clone();

        let memberships = organization_memberships_needing_trust(
            vec![org],
            UpgradeTokenAction::CreateIfNeeded,
            &store,
        );

        assert_eq!(memberships.len(), 1);
        assert_org_membership_eq(&memberships[0], &expected_org);
    }
}
