use bitwarden_core::key_management::{KeyIds, SymmetricKeyId};
use bitwarden_crypto::{KeyStoreContext, PublicKey};
use tracing::{debug, info, warn};

use super::{
    RotateUserKeysError,
    sync::SyncedAccountData,
    unlock::{V1EmergencyAccessMembership, V1OrganizationMembership},
};

struct UntrustedKeyError;

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
    pub(super) current_user_key_id: SymmetricKeyId,
    pub(super) new_user_key_id: SymmetricKeyId,
}

pub(super) fn make_rotation_context(
    sync: &SyncedAccountData,
    trusted_organization_public_keys: &[PublicKey],
    trusted_emergency_access_public_keys: &[PublicKey],
    ctx: &mut KeyStoreContext<KeyIds>,
) -> Result<RotationContext, RotateUserKeysError> {
    let v1_organization_memberships = filter_trusted_organization(
        sync.organization_memberships.as_slice(),
        trusted_organization_public_keys,
    )
    .map_err(|_| RotateUserKeysError::UntrustedKeyError)?;

    let v1_emergency_access_memberships = filter_trusted_emergency_access(
        sync.emergency_access_memberships.as_slice(),
        trusted_emergency_access_public_keys,
    )
    .map_err(|_| RotateUserKeysError::UntrustedKeyError)?;

    info!(
        "Existing user cryptographic version {:?}",
        sync.wrapped_account_cryptographic_state
    );
    let current_user_key_id = SymmetricKeyId::User;

    debug!("Generating new xchacha20-poly1305 user key for key rotation");
    let new_user_key_id =
        ctx.make_symmetric_key(bitwarden_crypto::SymmetricKeyAlgorithm::XChaCha20Poly1305);

    Ok(RotationContext {
        v1_organization_memberships,
        v1_emergency_access_memberships,
        current_user_key_id,
        new_user_key_id,
    })
}

#[cfg(test)]
mod tests {
    use bitwarden_core::key_management::{
        KeyIds, PrivateKeyId, SymmetricKeyId,
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
        RotateUserKeysError, filter_trusted_emergency_access, filter_trusted_organization,
        make_rotation_context,
    };

    fn make_org_membership(
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> (V1OrganizationMembership, PrivateKeyId) {
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
        ctx: &mut KeyStoreContext<KeyIds>,
    ) -> (V1EmergencyAccessMembership, PrivateKeyId) {
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

    fn make_test_sync(
        org_memberships: Vec<V1OrganizationMembership>,
        ea_memberships: Vec<V1EmergencyAccessMembership>,
        ctx: &mut KeyStoreContext<KeyIds>,
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
        let store: KeyStore<KeyIds> = KeyStore::default();
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
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (org1, _) = make_org_membership(&mut ctx);
        let (org2, _) = make_org_membership(&mut ctx);
        let trusted = [org1.public_key.clone(), org2.public_key.clone()];

        let result = filter_trusted_organization(&[org1, org2], &trusted);

        assert!(matches!(result, Ok(ref v) if v.len() == 2));
    }

    #[test]
    fn test_filter_trusted_org_one_untrusted() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (org1, _) = make_org_membership(&mut ctx);
        let (org2, _) = make_org_membership(&mut ctx);
        let trusted = [org1.public_key.clone()];

        let result = filter_trusted_organization(&[org1, org2], &trusted);

        assert!(result.is_err());
    }

    #[test]
    fn test_filter_trusted_org_empty_trusted_with_orgs() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (org, _) = make_org_membership(&mut ctx);

        let result = filter_trusted_organization(&[org], &[]);

        assert!(result.is_err());
    }

    #[test]
    fn test_filter_trusted_ea_empty_list() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (ea, _) = make_ea_membership(&mut ctx);
        let trusted = [ea.public_key.clone()];

        let result = filter_trusted_emergency_access(&[], &trusted);

        assert!(matches!(result, Ok(ref v) if v.is_empty()));
    }

    #[test]
    fn test_filter_trusted_ea_all_trusted() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (ea1, _) = make_ea_membership(&mut ctx);
        let (ea2, _) = make_ea_membership(&mut ctx);
        let trusted = [ea1.public_key.clone(), ea2.public_key.clone()];

        let result = filter_trusted_emergency_access(&[ea1, ea2], &trusted);

        assert!(matches!(result, Ok(ref v) if v.len() == 2));
    }

    #[test]
    fn test_filter_trusted_ea_one_untrusted() {
        let store: KeyStore<KeyIds> = KeyStore::default();
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
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (ea, _) = make_ea_membership(&mut ctx);

        let result = filter_trusted_emergency_access(&[ea], &[]);

        assert!(result.is_err());
    }

    #[test]
    fn test_make_rotation_context_empty_data() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let sync = make_test_sync(vec![], vec![], &mut ctx);

        let result = make_rotation_context(&sync, &[], &[], &mut ctx);

        let rotation_ctx = result.expect("should succeed");
        assert!(rotation_ctx.v1_organization_memberships.is_empty());
        assert!(rotation_ctx.v1_emergency_access_memberships.is_empty());
        assert_eq!(rotation_ctx.current_user_key_id, SymmetricKeyId::User);
        assert_ne!(
            rotation_ctx.new_user_key_id,
            rotation_ctx.current_user_key_id
        );
    }

    #[test]
    fn test_make_rotation_context_trusted_org_and_ea() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (org, _) = make_org_membership(&mut ctx);
        let (ea, _) = make_ea_membership(&mut ctx);
        let trusted_orgs = [org.public_key.clone()];
        let trusted_eas = [ea.public_key.clone()];
        let sync = make_test_sync(vec![org], vec![ea], &mut ctx);

        let result = make_rotation_context(&sync, &trusted_orgs, &trusted_eas, &mut ctx);

        let rotation_ctx = result.expect("should succeed");
        assert_eq!(rotation_ctx.v1_organization_memberships.len(), 1);
        assert_eq!(rotation_ctx.v1_emergency_access_memberships.len(), 1);
    }

    #[test]
    fn test_make_rotation_context_untrusted_org_returns_error() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (org, _) = make_org_membership(&mut ctx);
        let sync = make_test_sync(vec![org], vec![], &mut ctx);

        let result = make_rotation_context(&sync, &[], &[], &mut ctx);

        assert!(matches!(
            result,
            Err(RotateUserKeysError::UntrustedKeyError)
        ));
    }

    #[test]
    fn test_make_rotation_context_untrusted_ea_returns_error() {
        let store: KeyStore<KeyIds> = KeyStore::default();
        let mut ctx = store.context_mut();
        let (ea, _) = make_ea_membership(&mut ctx);
        let sync = make_test_sync(vec![], vec![ea], &mut ctx);

        let result = make_rotation_context(&sync, &[], &[], &mut ctx);

        assert!(matches!(
            result,
            Err(RotateUserKeysError::UntrustedKeyError)
        ));
    }
}
