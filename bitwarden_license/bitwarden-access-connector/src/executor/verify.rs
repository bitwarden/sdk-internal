//! Cross-checks a claim's two sealed values against each other and the plaintext claim (checks
//! 1–7). Check 8, the pre-flight cipher read, needs the network and lives in `executor::rotation`.
//!
//! Only [`verify`] can construct a [`VerifiedJob`], so `rotation::execute` never reads an
//! uncross-checked claim field.

use bitwarden_crypto::{EncString, safe::DataEnvelope};
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

/// Why [`verify`] refused a claim. Carries no claim or blob values, only which check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SealRejection {
    MissingTargetBlob,
    MissingConfigBlob,
    TargetBlobInvalid,
    ConfigBlobInvalid,
    TargetSystemIdMismatch,
    CipherIdMismatch,
    TargetMethodNotAutomatic,
    /// A legitimate `Automatic` target always seals a kind.
    TargetKindMissing,
    PolicyRejected,
}

impl SealRejection {
    /// A `'static` name, safe to report in a [`crate::error::SafeDetail`].
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

/// A claim cross-checked by [`verify`]; private fields keep it constructible only there.
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
    terminate_sessions: bool,
    execute_by: DateTime<Utc>,
}

impl VerifiedJob {
    pub(crate) fn attempt_id(&self) -> Uuid {
        self.attempt_id
    }

    pub(crate) fn job_id(&self) -> Uuid {
        self.job_id
    }

    pub(crate) fn target_system_id(&self) -> Uuid {
        self.target_system_id
    }

    /// For logging only.
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

    /// Passed verbatim to integrations, which must treat it as untrusted input.
    pub(crate) fn account_identity(&self) -> &str {
        &self.account_identity
    }

    pub(crate) fn terminate_sessions(&self) -> bool {
        self.terminate_sessions
    }

    /// No target-side step starts after this.
    pub(crate) fn execute_by(&self) -> DateTime<Utc> {
        self.execute_by
    }
}

/// Runs checks 1–7 on a claim, rejecting it with a [`SealRejection`] on the first failure.
pub(crate) fn verify(
    snapshot: WorkSnapshot,
    key_store: &AccessConnectorKeyStore,
) -> Result<VerifiedJob, SealRejection> {
    // Check 1: both halves of each sealed value must be present and parse.
    let (target_envelope, target_key) = snapshot
        .target_system_sealed_data
        .as_deref()
        .zip(snapshot.target_system_wrapped_key.as_deref())
        .ok_or(SealRejection::MissingTargetBlob)?;
    let (config_envelope, config_key) = snapshot
        .rotation_config_sealed_data
        .as_deref()
        .zip(snapshot.rotation_config_wrapped_key.as_deref())
        .ok_or(SealRejection::MissingConfigBlob)?;

    let target_envelope: DataEnvelope = target_envelope
        .parse()
        .map_err(|_| SealRejection::TargetBlobInvalid)?;
    let config_envelope: DataEnvelope = config_envelope
        .parse()
        .map_err(|_| SealRejection::ConfigBlobInvalid)?;

    let mut ctx = key_store.context_mut();

    let target: TargetSystemSealedV1 = unseal_target_system::<AccessConnectorKeySlotIds>(
        &target_envelope,
        &EncString::from(target_key),
        &AccessConnectorSymmSlotId::Organization,
        &mut ctx,
    )
    .map_err(|_| SealRejection::TargetBlobInvalid)?;

    let config: RotationConfigSealedV1 = unseal_rotation_config::<AccessConnectorKeySlotIds>(
        &config_envelope,
        &EncString::from(config_key),
        &AccessConnectorSymmSlotId::Organization,
        &mut ctx,
    )
    .map_err(|_| SealRejection::ConfigBlobInvalid)?;

    // Check 2.
    if snapshot.target_system_id != target.target_system_id
        || snapshot.target_system_id != config.target_system_id
    {
        return Err(SealRejection::TargetSystemIdMismatch);
    }

    // Check 3.
    if snapshot.cipher_id != config.cipher_id {
        return Err(SealRejection::CipherIdMismatch);
    }

    // Check 4: reads the sealed method only; the server's plaintext copy is advisory.
    if target.method != SealedTargetSystemMethod::Automatic {
        return Err(SealRejection::TargetMethodNotAutomatic);
    }

    // Check 5: kind, policy, and account identity come from the blobs only.
    let kind = target.kind.ok_or(SealRejection::TargetKindMissing)?;

    // Check 6.
    target
        .password_policy
        .validate()
        .map_err(|_| SealRejection::PolicyRejected)?;

    // Check 7: unsupported termination is ANDed to false, not a rejection.
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

/// Fixture builders shared with the `executor` tests.
#[cfg(test)]
pub(crate) mod test_support {
    use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};
    use bitwarden_pam_sealed::Sealed;

    use super::*;

    /// `(sealedData, wrappedKey)` as sent over the wire.
    pub(crate) type SealedStrings = (String, String);

    /// A key store holding a fresh organization key, which is also returned.
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
        target_blob: Option<SealedStrings>,
        config_blob: Option<SealedStrings>,
    ) -> WorkSnapshot {
        let (target_data, target_key) = target_blob.unzip();
        let (config_data, config_key) = config_blob.unzip();
        WorkSnapshot {
            attempt_id,
            job_id,
            target_system_id,
            target_system_name: "test-system".to_owned(),
            cipher_id,
            target_system_sealed_data: target_data,
            target_system_wrapped_key: target_key,
            rotation_config_sealed_data: config_data,
            rotation_config_wrapped_key: config_key,
            execute_by: Utc::now() + chrono::Duration::minutes(5),
        }
    }

    pub(crate) fn sealed_pair(
        store: &AccessConnectorKeyStore,
        target: TargetSystemSealedV1,
        config: RotationConfigSealedV1,
    ) -> (SealedStrings, SealedStrings) {
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
        (strings(target_blob), strings(config_blob))
    }

    /// Wire form of a [`Sealed`]: `(sealedData, wrappedKey)`.
    pub(crate) fn strings(sealed: Sealed) -> SealedStrings {
        (sealed.envelope.to_string(), sealed.wrapped_key.to_string())
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
    fn target_sealed_data_without_wrapped_key_is_rejected() {
        let (store, _org_key) = store_with_org_key();
        let target_system_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();
        let (target_blob, config_blob) = sealed_pair(
            &store,
            sample_target(target_system_id),
            sample_config(target_system_id, cipher_id),
        );

        let mut snapshot = work_snapshot(
            Uuid::new_v4(),
            Uuid::new_v4(),
            target_system_id,
            cipher_id,
            Some(target_blob),
            Some(config_blob),
        );
        snapshot.target_system_wrapped_key = None;
        assert_eq!(
            verify(snapshot, &store).unwrap_err(),
            SealRejection::MissingTargetBlob
        );
    }

    #[test]
    fn config_sealed_data_without_wrapped_key_is_rejected() {
        let (store, _org_key) = store_with_org_key();
        let target_system_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();
        let (target_blob, config_blob) = sealed_pair(
            &store,
            sample_target(target_system_id),
            sample_config(target_system_id, cipher_id),
        );

        let mut snapshot = work_snapshot(
            Uuid::new_v4(),
            Uuid::new_v4(),
            target_system_id,
            cipher_id,
            Some(target_blob),
            Some(config_blob),
        );
        snapshot.rotation_config_wrapped_key = None;
        assert_eq!(
            verify(snapshot, &store).unwrap_err(),
            SealRejection::MissingConfigBlob
        );
    }

    #[test]
    fn unparseable_wrapped_key_is_rejected() {
        let (store, _org_key) = store_with_org_key();
        let target_system_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();
        let ((target_data, _), config_blob) = sealed_pair(
            &store,
            sample_target(target_system_id),
            sample_config(target_system_id, cipher_id),
        );

        let snapshot = work_snapshot(
            Uuid::new_v4(),
            Uuid::new_v4(),
            target_system_id,
            cipher_id,
            Some((target_data, "not a wrapped key".to_owned())),
            Some(config_blob),
        );
        assert_eq!(
            verify(snapshot, &store).unwrap_err(),
            SealRejection::TargetBlobInvalid
        );
    }

    #[test]
    fn wrapped_key_from_a_different_seal_is_rejected() {
        // Envelope from one seal, wrapped key from another: the key does not open the envelope.
        let (store, _org_key) = store_with_org_key();
        let target_system_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();
        let ((target_data, _), config_blob) = sealed_pair(
            &store,
            sample_target(target_system_id),
            sample_config(target_system_id, cipher_id),
        );
        let ((_, other_key), _) = sealed_pair(
            &store,
            sample_target(target_system_id),
            sample_config(target_system_id, cipher_id),
        );

        let snapshot = work_snapshot(
            Uuid::new_v4(),
            Uuid::new_v4(),
            target_system_id,
            cipher_id,
            Some((target_data, other_key)),
            Some(config_blob),
        );
        assert_eq!(
            verify(snapshot, &store).unwrap_err(),
            SealRejection::TargetBlobInvalid
        );
    }

    #[test]
    fn garbage_target_blob_is_rejected() {
        let (store, _org_key) = store_with_org_key();
        let target_system_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();
        let ((_, target_key), config_blob) = sealed_pair(
            &store,
            sample_target(target_system_id),
            sample_config(target_system_id, cipher_id),
        );

        let snapshot = work_snapshot(
            Uuid::new_v4(),
            Uuid::new_v4(),
            target_system_id,
            cipher_id,
            Some(("not a sealed blob".to_owned(), target_key)),
            Some(config_blob),
        );
        assert_eq!(
            verify(snapshot, &store).unwrap_err(),
            SealRejection::TargetBlobInvalid
        );
    }

    #[test]
    fn target_blob_sealed_under_a_different_org_key_is_rejected() {
        let (store, _org_key) = store_with_org_key();
        let (other_store, _other_key) = store_with_org_key();
        let target_system_id = Uuid::new_v4();
        let cipher_id = Uuid::new_v4();

        let wrong_key_target_blob = {
            let mut ctx = other_store.context_mut();
            strings(
                seal_target_system::<AccessConnectorKeySlotIds>(
                    sample_target(target_system_id),
                    &AccessConnectorSymmSlotId::Organization,
                    &mut ctx,
                )
                .expect("seal under other store's key"),
            )
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
        // A config swapped in from another rotation config: same target, different cipher.
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
            strings(
                seal_rotation_config::<AccessConnectorKeySlotIds>(
                    sample_config(target_system_id, other_cipher_id),
                    &AccessConnectorSymmSlotId::Organization,
                    &mut ctx,
                )
                .expect("seal a different config"),
            )
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
            strings(
                seal_target_system::<AccessConnectorKeySlotIds>(
                    sample_target(other_target_id),
                    &AccessConnectorSymmSlotId::Organization,
                    &mut ctx,
                )
                .expect("seal a different target"),
            )
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
