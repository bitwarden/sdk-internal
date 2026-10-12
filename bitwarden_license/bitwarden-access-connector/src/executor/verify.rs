//! Verifies a claim's two sealed blobs against each other and against the plaintext claim before
//! any plaintext claim field is trusted (checks 1–7). Check 8, the pre-flight cipher read, happens
//! later in `executor::rotation`, since it needs a network round trip this sync function can't
//! make.
//!
//! [`verify`] is the only place that can construct [`VerifiedJob`]: its fields are private, so
//! `rotation::execute` can never read a plaintext claim field that wasn't cross-checked against
//! the sealed blobs.

use bitwarden_pam_sealed::{
    RotationConfigSealedV1, SealedPasswordPolicy, SealedTargetSystemMethod, TargetSystemSealedV1,
    unseal_rotation_config, unseal_target_system,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    api::models::{TargetKind, WorkSnapshot},
    crypto::{AccessConnectorKeySlotIds, AccessConnectorKeyStore, AccessConnectorSymmSlotId},
};

/// Why [`verify`] refused a claim. Never carries field values from the claim or the sealed blobs —
/// only which check failed, reported as `FailureCode::SealedDataRejected`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SealRejection {
    /// The claim carried no `target_system_sealed_data` blob (check 1).
    MissingTargetBlob,
    /// The claim carried no `rotation_config_sealed_data` blob (check 1).
    MissingConfigBlob,
    /// The target blob did not unseal: wrong key, envelope, namespace, or version (check 1).
    TargetBlobInvalid,
    /// The rotation-config blob did not unseal (check 1).
    ConfigBlobInvalid,
    /// The claim's `target_system_id`, the target blob's own `target_system_id`, and the config
    /// blob's `target_system_id` do not all agree (check 2).
    TargetSystemIdMismatch,
    /// The claim's `cipher_id` does not match the rotation-config blob's `cipher_id` (check 3).
    CipherIdMismatch,
    /// The sealed target's `method` is not `Automatic` (check 4).
    TargetMethodNotAutomatic,
    /// The sealed target's `method` is `Automatic` but `kind` is absent — a malformed blob, since
    /// a legitimate automatic target always seals a kind (check 5).
    TargetKindMissing,
    /// The sealed password policy fails the shared generator-validity check (check 6): no
    /// character class enabled, or length bounds outside the generator's supported range.
    PolicyRejected,
}

impl SealRejection {
    /// A `'static` name for this rejection, safe to report in a [`crate::error::SafeDetail`].
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::MissingTargetBlob => "missing_target_blob",
            Self::MissingConfigBlob => "missing_config_blob",
            Self::TargetBlobInvalid => "target_blob_invalid",
            Self::ConfigBlobInvalid => "config_blob_invalid",
            Self::TargetSystemIdMismatch => "target_system_id_mismatch",
            Self::CipherIdMismatch => "cipher_id_mismatch",
            Self::TargetMethodNotAutomatic => "target_method_not_automatic",
            Self::TargetKindMissing => "target_kind_missing",
            Self::PolicyRejected => "policy_rejected",
        }
    }
}

/// A claim whose sealed blobs have been unsealed and cross-checked against each other and the
/// plaintext claim by [`verify`]. Fields are private so only [`verify`] can construct one, keeping
/// `rotation::execute` from ever reading an uncross-checked claim field.
#[derive(Debug)]
pub(crate) struct VerifiedJob {
    attempt_id: Uuid,
    job_id: Uuid,
    target_system_id: Uuid,
    target_system_name: String,
    cipher_id: Uuid,
    kind: TargetKind,
    password_policy: SealedPasswordPolicy,
    account_identity: String,
    /// `config.terminate_sessions && target.supports_session_termination == Some(true)`
    /// (check 7) — never the raw config flag alone.
    terminate_sessions: bool,
    execute_by: DateTime<Utc>,
}

impl VerifiedJob {
    /// Keys every attempt-scoped request (cipher read/write, outcome reports).
    pub(crate) fn attempt_id(&self) -> Uuid {
        self.attempt_id
    }

    pub(crate) fn job_id(&self) -> Uuid {
        self.job_id
    }

    pub(crate) fn target_system_id(&self) -> Uuid {
        self.target_system_id
    }

    /// Display name of the target system, for logging. Not security-relevant.
    pub(crate) fn target_system_name(&self) -> &str {
        &self.target_system_name
    }

    pub(crate) fn cipher_id(&self) -> Uuid {
        self.cipher_id
    }

    pub(crate) fn kind(&self) -> TargetKind {
        self.kind
    }

    pub(crate) fn password_policy(&self) -> &SealedPasswordPolicy {
        &self.password_policy
    }

    /// Opaque account identity passed verbatim to the integration layer. Treated as untrusted
    /// input by integrations: never interpolated unsanitized into a shell command or query.
    pub(crate) fn account_identity(&self) -> &str {
        &self.account_identity
    }

    pub(crate) fn terminate_sessions(&self) -> bool {
        self.terminate_sessions
    }

    /// Lease deadline: no target-side step starts after it.
    pub(crate) fn execute_by(&self) -> DateTime<Utc> {
        self.execute_by
    }
}

/// Implements checks 1–7: unseals both blobs, cross-checks every ID, requires an automatic
/// target, and checks the policy is one the generator can satisfy.
pub(crate) fn verify(
    snapshot: WorkSnapshot,
    key_store: &AccessConnectorKeyStore,
) -> Result<VerifiedJob, SealRejection> {
    // Check 1: both blobs must be present and must unseal.
    let target_blob = snapshot
        .target_system_sealed_data
        .as_deref()
        .ok_or(SealRejection::MissingTargetBlob)?;
    let config_blob = snapshot
        .rotation_config_sealed_data
        .as_deref()
        .ok_or(SealRejection::MissingConfigBlob)?;

    let mut ctx = key_store.context_mut();

    let target: TargetSystemSealedV1 = unseal_target_system::<AccessConnectorKeySlotIds>(
        target_blob,
        &AccessConnectorSymmSlotId::Organization,
        &mut ctx,
    )
    .map_err(|_| SealRejection::TargetBlobInvalid)?;

    let config: RotationConfigSealedV1 = unseal_rotation_config::<AccessConnectorKeySlotIds>(
        config_blob,
        &AccessConnectorSymmSlotId::Organization,
        &mut ctx,
    )
    .map_err(|_| SealRejection::ConfigBlobInvalid)?;

    // Check 2: the claim, the target blob, and the config blob must all name the same target.
    if snapshot.target_system_id != target.target_system_id
        || snapshot.target_system_id != config.target_system_id
    {
        return Err(SealRejection::TargetSystemIdMismatch);
    }

    // Check 3: the claim and the config blob must name the same cipher.
    if snapshot.cipher_id != config.cipher_id {
        return Err(SealRejection::CipherIdMismatch);
    }

    // Check 4: only an automatic target may run; a manual target's plaintext `method` on the
    // server is purely advisory, so this reads the sealed copy only.
    if target.method != SealedTargetSystemMethod::Automatic {
        return Err(SealRejection::TargetMethodNotAutomatic);
    }

    // Check 5: kind, policy, and account identity come from the blobs only, never the plaintext
    // claim.
    let kind = target.kind.ok_or(SealRejection::TargetKindMissing)?;

    // Check 6: the policy must be one the generator can satisfy (at least one class, length
    // within the generator's supported range).
    target
        .password_policy
        .validate()
        .map_err(|_| SealRejection::PolicyRejected)?;

    // Check 7: terminate only if the config asks for it and the target can honor it; unsupported
    // is ANDed to false, not a rejection.
    let terminate_sessions =
        config.terminate_sessions && target.supports_session_termination == Some(true);

    Ok(VerifiedJob {
        attempt_id: snapshot.attempt_id,
        job_id: snapshot.job_id,
        target_system_id: snapshot.target_system_id,
        target_system_name: snapshot.target_system_name,
        cipher_id: snapshot.cipher_id,
        kind: TargetKind::from(kind),
        password_policy: target.password_policy,
        account_identity: config.account_identity,
        terminate_sessions,
        execute_by: snapshot.execute_by,
    })
}

/// Test-only fixture builders shared with `executor::rotation` and `executor::mod`'s tests, which
/// need a real [`VerifiedJob`] without repeating the sealing boilerplate at every call site.
#[cfg(test)]
pub(crate) mod test_support {
    use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};

    use super::*;

    /// A key store with a freshly generated organization key installed at the `Organization`
    /// slot, plus the key itself (for sealing fixtures under a *different* key in tamper tests).
    pub(crate) fn store_with_org_key() -> (AccessConnectorKeyStore, SymmetricCryptoKey) {
        let store = AccessConnectorKeyStore::default();
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        #[allow(deprecated)]
        store
            .context_mut()
            .set_symmetric_key(AccessConnectorSymmSlotId::Organization, org_key.clone())
            .expect("set_symmetric_key");
        (store, org_key)
    }

    /// A generator-valid policy: all classes enabled, length 20.
    pub(crate) fn strong_policy() -> SealedPasswordPolicy {
        SealedPasswordPolicy {
            min_length: 20,
            max_length: 20,
            include_uppercase: true,
            include_lowercase: true,
            include_digits: true,
            include_symbols: true,
        }
    }

    pub(crate) fn sample_target(target_system_id: Uuid) -> TargetSystemSealedV1 {
        TargetSystemSealedV1 {
            target_system_id,
            method: SealedTargetSystemMethod::Automatic,
            kind: Some(bitwarden_pam_sealed::SealedTargetSystemKind::CustomScript),
            password_policy: strong_policy(),
            supports_session_termination: Some(true),
        }
    }

    pub(crate) fn sample_config(target_system_id: Uuid, cipher_id: Uuid) -> RotationConfigSealedV1 {
        RotationConfigSealedV1 {
            target_system_id,
            cipher_id,
            account_identity: "svc-rotation@example.com".to_owned(),
            terminate_sessions: true,
        }
    }

    pub(crate) fn work_snapshot(
        attempt_id: Uuid,
        job_id: Uuid,
        target_system_id: Uuid,
        cipher_id: Uuid,
        target_blob: Option<String>,
        config_blob: Option<String>,
    ) -> WorkSnapshot {
        WorkSnapshot {
            attempt_id,
            job_id,
            target_system_id,
            target_system_name: "test-system".to_owned(),
            cipher_id,
            target_system_sealed_data: target_blob,
            rotation_config_sealed_data: config_blob,
            execute_by: Utc::now() + chrono::Duration::minutes(5),
        }
    }

    /// Seals `target` and `config` under `store`'s organization key, returning both opaque blobs.
    pub(crate) fn sealed_pair(
        store: &AccessConnectorKeyStore,
        target: TargetSystemSealedV1,
        config: RotationConfigSealedV1,
    ) -> (String, String) {
        let mut ctx = store.context_mut();
        let target_blob = bitwarden_pam_sealed::seal_target_system::<AccessConnectorKeySlotIds>(
            target,
            &AccessConnectorSymmSlotId::Organization,
            &mut ctx,
        )
        .expect("seal target");
        let config_blob = bitwarden_pam_sealed::seal_rotation_config::<AccessConnectorKeySlotIds>(
            config,
            &AccessConnectorSymmSlotId::Organization,
            &mut ctx,
        )
        .expect("seal config");
        (target_blob, config_blob)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_pam_sealed::{seal_rotation_config, seal_target_system};

    use super::{test_support::*, *};

    #[test]
    fn happy_path_produces_verified_job() {
        let (store, _org_key) = store_with_org_key();
        let target_system_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();
        let attempt_id = Uuid::new_v4();
        let job_id = Uuid::new_v4();

        let (target_blob, config_blob) = sealed_pair(
            &store,
            sample_target(target_system_id),
            sample_config(target_system_id, cipher_id),
        );

        let snapshot = work_snapshot(
            attempt_id,
            job_id,
            target_system_id,
            cipher_id,
            Some(target_blob),
            Some(config_blob),
        );

        let job = verify(snapshot, &store).expect("well-formed claim should verify");

        assert_eq!(job.attempt_id(), attempt_id);
        assert_eq!(job.job_id(), job_id);
        assert_eq!(job.target_system_id(), target_system_id);
        assert_eq!(job.cipher_id(), cipher_id);
        assert_eq!(job.kind(), TargetKind::CustomScript);
        assert_eq!(job.account_identity(), "svc-rotation@example.com");
        assert!(job.terminate_sessions());
    }

    #[test]
    fn missing_target_blob_is_rejected() {
        let (store, _org_key) = store_with_org_key();
        let target_system_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();
        let (_target_blob, config_blob) = sealed_pair(
            &store,
            sample_target(target_system_id),
            sample_config(target_system_id, cipher_id),
        );

        let snapshot = work_snapshot(
            Uuid::new_v4(),
            Uuid::new_v4(),
            target_system_id,
            cipher_id,
            None,
            Some(config_blob),
        );
        assert_eq!(
            verify(snapshot, &store).unwrap_err(),
            SealRejection::MissingTargetBlob
        );
    }

    #[test]
    fn missing_config_blob_is_rejected() {
        let (store, _org_key) = store_with_org_key();
        let target_system_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();
        let (target_blob, _config_blob) = sealed_pair(
            &store,
            sample_target(target_system_id),
            sample_config(target_system_id, cipher_id),
        );

        let snapshot = work_snapshot(
            Uuid::new_v4(),
            Uuid::new_v4(),
            target_system_id,
            cipher_id,
            Some(target_blob),
            None,
        );
        assert_eq!(
            verify(snapshot, &store).unwrap_err(),
            SealRejection::MissingConfigBlob
        );
    }

    #[test]
    fn garbage_target_blob_is_rejected() {
        let (store, _org_key) = store_with_org_key();
        let target_system_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();
        let (_target_blob, config_blob) = sealed_pair(
            &store,
            sample_target(target_system_id),
            sample_config(target_system_id, cipher_id),
        );

        let snapshot = work_snapshot(
            Uuid::new_v4(),
            Uuid::new_v4(),
            target_system_id,
            cipher_id,
            Some("not a sealed blob".to_owned()),
            Some(config_blob),
        );
        assert_eq!(
            verify(snapshot, &store).unwrap_err(),
            SealRejection::TargetBlobInvalid
        );
    }

    #[test]
    fn target_blob_sealed_under_a_different_org_key_is_rejected() {
        // A connector holding a different key (or an attacker without the org key) cannot
        // unseal a blob sealed for this organization.
        let (store, _org_key) = store_with_org_key();
        let (other_store, _other_key) = store_with_org_key();
        let target_system_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();

        let wrong_key_target_blob = {
            let mut ctx = other_store.context_mut();
            seal_target_system::<AccessConnectorKeySlotIds>(
                sample_target(target_system_id),
                &AccessConnectorSymmSlotId::Organization,
                &mut ctx,
            )
            .expect("seal under other store's key")
        };
        let (_target_blob, config_blob) = sealed_pair(
            &store,
            sample_target(target_system_id),
            sample_config(target_system_id, cipher_id),
        );

        let snapshot = work_snapshot(
            Uuid::new_v4(),
            Uuid::new_v4(),
            target_system_id,
            cipher_id,
            Some(wrong_key_target_blob),
            Some(config_blob),
        );
        assert_eq!(
            verify(snapshot, &store).unwrap_err(),
            SealRejection::TargetBlobInvalid
        );
    }

    #[test]
    fn config_blob_from_a_different_config_is_rejected() {
        // The config blob was sealed for the same target but a different cipher than the claim
        // and target blob agree on — a config "swapped in" from another rotation config.
        let (store, _org_key) = store_with_org_key();
        let target_system_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();
        let other_cipher_id = Uuid::new_v4();

        let (target_blob, _matching_config_blob) = sealed_pair(
            &store,
            sample_target(target_system_id),
            sample_config(target_system_id, cipher_id),
        );
        let wrong_config_blob = {
            let mut ctx = store.context_mut();
            seal_rotation_config::<AccessConnectorKeySlotIds>(
                sample_config(target_system_id, other_cipher_id),
                &AccessConnectorSymmSlotId::Organization,
                &mut ctx,
            )
            .expect("seal a different config")
        };

        let snapshot = work_snapshot(
            Uuid::new_v4(),
            Uuid::new_v4(),
            target_system_id,
            cipher_id,
            Some(target_blob),
            Some(wrong_config_blob),
        );
        assert_eq!(
            verify(snapshot, &store).unwrap_err(),
            SealRejection::CipherIdMismatch
        );
    }

    #[test]
    fn target_blob_from_a_different_target_is_rejected() {
        let (store, _org_key) = store_with_org_key();
        let target_system_id = Uuid::new_v4();
        let other_target_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();

        let wrong_target_blob = {
            let mut ctx = store.context_mut();
            seal_target_system::<AccessConnectorKeySlotIds>(
                sample_target(other_target_id),
                &AccessConnectorSymmSlotId::Organization,
                &mut ctx,
            )
            .expect("seal a different target")
        };
        let (_matching_target_blob, config_blob) = sealed_pair(
            &store,
            sample_target(target_system_id),
            sample_config(target_system_id, cipher_id),
        );

        let snapshot = work_snapshot(
            Uuid::new_v4(),
            Uuid::new_v4(),
            target_system_id,
            cipher_id,
            Some(wrong_target_blob),
            Some(config_blob),
        );
        assert_eq!(
            verify(snapshot, &store).unwrap_err(),
            SealRejection::TargetSystemIdMismatch
        );
    }

    #[test]
    fn claim_target_id_differs_from_sealed_blobs_is_rejected() {
        let (store, _org_key) = store_with_org_key();
        let real_target_id = Uuid::new_v4();
        let claim_target_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();

        let (target_blob, config_blob) = sealed_pair(
            &store,
            sample_target(real_target_id),
            sample_config(real_target_id, cipher_id),
        );

        let snapshot = work_snapshot(
            Uuid::new_v4(),
            Uuid::new_v4(),
            claim_target_id,
            cipher_id,
            Some(target_blob),
            Some(config_blob),
        );
        assert_eq!(
            verify(snapshot, &store).unwrap_err(),
            SealRejection::TargetSystemIdMismatch
        );
    }

    #[test]
    fn claim_cipher_id_differs_from_config_blob_is_rejected() {
        let (store, _org_key) = store_with_org_key();
        let target_system_id = Uuid::new_v4();
        let real_cipher_id = Uuid::new_v4();
        let claim_cipher_id = Uuid::new_v4();

        let (target_blob, config_blob) = sealed_pair(
            &store,
            sample_target(target_system_id),
            sample_config(target_system_id, real_cipher_id),
        );

        let snapshot = work_snapshot(
            Uuid::new_v4(),
            Uuid::new_v4(),
            target_system_id,
            claim_cipher_id,
            Some(target_blob),
            Some(config_blob),
        );
        assert_eq!(
            verify(snapshot, &store).unwrap_err(),
            SealRejection::CipherIdMismatch
        );
    }

    #[test]
    fn manual_target_method_is_rejected() {
        let (store, _org_key) = store_with_org_key();
        let target_system_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();

        let manual_target = TargetSystemSealedV1 {
            method: SealedTargetSystemMethod::Manual,
            kind: None,
            supports_session_termination: None,
            ..sample_target(target_system_id)
        };
        let (target_blob, config_blob) = sealed_pair(
            &store,
            manual_target,
            sample_config(target_system_id, cipher_id),
        );

        let snapshot = work_snapshot(
            Uuid::new_v4(),
            Uuid::new_v4(),
            target_system_id,
            cipher_id,
            Some(target_blob),
            Some(config_blob),
        );
        assert_eq!(
            verify(snapshot, &store).unwrap_err(),
            SealRejection::TargetMethodNotAutomatic
        );
    }

    #[test]
    fn automatic_target_with_missing_kind_is_rejected() {
        let (store, _org_key) = store_with_org_key();
        let target_system_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();

        let malformed_target = TargetSystemSealedV1 {
            kind: None,
            ..sample_target(target_system_id)
        };
        let (target_blob, config_blob) = sealed_pair(
            &store,
            malformed_target,
            sample_config(target_system_id, cipher_id),
        );

        let snapshot = work_snapshot(
            Uuid::new_v4(),
            Uuid::new_v4(),
            target_system_id,
            cipher_id,
            Some(target_blob),
            Some(config_blob),
        );
        assert_eq!(
            verify(snapshot, &store).unwrap_err(),
            SealRejection::TargetKindMissing
        );
    }

    #[test]
    fn policy_with_no_character_classes_is_rejected() {
        let (store, _org_key) = store_with_org_key();
        let target_system_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();

        let invalid_target = TargetSystemSealedV1 {
            password_policy: SealedPasswordPolicy {
                min_length: 20,
                max_length: 20,
                include_uppercase: false,
                include_lowercase: false,
                include_digits: false,
                include_symbols: false,
            },
            ..sample_target(target_system_id)
        };
        let (target_blob, config_blob) = sealed_pair(
            &store,
            invalid_target,
            sample_config(target_system_id, cipher_id),
        );

        let snapshot = work_snapshot(
            Uuid::new_v4(),
            Uuid::new_v4(),
            target_system_id,
            cipher_id,
            Some(target_blob),
            Some(config_blob),
        );
        assert_eq!(
            verify(snapshot, &store).unwrap_err(),
            SealRejection::PolicyRejected
        );
    }

    #[test]
    fn terminate_requested_but_unsupported_is_anded_to_false_not_rejected() {
        let (store, _org_key) = store_with_org_key();
        let target_system_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();

        let target = TargetSystemSealedV1 {
            supports_session_termination: Some(false),
            ..sample_target(target_system_id)
        };
        let config = RotationConfigSealedV1 {
            terminate_sessions: true,
            ..sample_config(target_system_id, cipher_id)
        };
        let (target_blob, config_blob) = sealed_pair(&store, target, config);

        let snapshot = work_snapshot(
            Uuid::new_v4(),
            Uuid::new_v4(),
            target_system_id,
            cipher_id,
            Some(target_blob),
            Some(config_blob),
        );

        let job = verify(snapshot, &store)
            .expect("an unsupported termination request must not be a rejection");
        assert!(!job.terminate_sessions());
    }
}
