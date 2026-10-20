//! A claimed rotation job and its verification.
//!
//! [`WorkSnapshot::verify`] cross-checks a claim's two sealed values against each other and the
//! plaintext claim (checks 1–7). Check 8, the pre-flight cipher read, needs the network and lives
//! in the access connector's executor.
//!
//! Only [`WorkSnapshot::verify`] can construct a [`VerifiedJob`], so the connector never reads an
//! unchecked claim field.

use bitwarden_api_api::models::RotationClaimResponseModel;
use bitwarden_core::{
    MissingFieldError, OrganizationId,
    key_management::{KeySlotIds, SymmetricKeySlotId},
    require,
};
use bitwarden_crypto::{EncString, KeyStore, safe::DataEnvelope};
use bitwarden_generators::PasswordGeneratorRequest;
use bitwarden_pam_sealed::{
    GENERATOR_MAX_LENGTH, GENERATOR_MIN_LENGTH, PasswordPolicyError, RotationConfigSealedV1,
    SealedPasswordPolicy, SealedTargetSystemKind, SealedTargetSystemMethod, TargetSystemSealedV1,
    unseal_rotation_config, unseal_target_system,
};
use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

/// The work snapshot returned by a successful claim; [`WorkSnapshot::verify`] checks it before any
/// field is trusted.
#[derive(Debug, Clone)]
pub struct WorkSnapshot {
    /// Keys every attempt-scoped request (cipher read/write, outcome reports).
    pub attempt_id: Uuid,
    /// The rotation job.
    pub job_id: Uuid,
    /// The target system, as the server claims it.
    pub target_system_id: Uuid,
    /// For logging only.
    pub target_system_name: String,
    /// The cipher to rotate, as the server claims it.
    pub cipher_id: Uuid,
    /// The sealed target system envelope.
    pub target_system_sealed_data: Option<String>,
    /// The key wrapping the target system envelope.
    pub target_system_wrapped_key: Option<String>,
    /// The sealed rotation config envelope.
    pub rotation_config_sealed_data: Option<String>,
    /// The key wrapping the rotation config envelope.
    pub rotation_config_wrapped_key: Option<String>,
    /// Lease deadline: no target-side step starts after it.
    pub execute_by: DateTime<Utc>,
}

/// Errors from parsing a claim response. They never include payload content.
#[derive(Debug, Error)]
pub enum WorkSnapshotError {
    /// The response was missing a required field.
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    /// `executeBy` was not a valid timestamp.
    #[error("invalid executeBy timestamp")]
    InvalidExecuteBy,
}

impl TryFrom<RotationClaimResponseModel> for WorkSnapshot {
    type Error = WorkSnapshotError;

    fn try_from(model: RotationClaimResponseModel) -> Result<Self, Self::Error> {
        let attempt_id = require!(model.attempt_id);
        let job_id = require!(model.job_id);
        let target_system_id = require!(model.target_system_id);
        let target_system_name = require!(model.target_system_name);
        let cipher_id = require!(model.cipher_id);

        let execute_by = require!(model.execute_by)
            .parse::<DateTime<Utc>>()
            .map_err(|_| WorkSnapshotError::InvalidExecuteBy)?;

        // The sealed halves are not required here: a missing one is rejected by `verify`.
        Ok(Self {
            attempt_id,
            job_id,
            target_system_id,
            target_system_name,
            cipher_id,
            target_system_sealed_data: model.target_system_sealed_data,
            target_system_wrapped_key: model.target_system_wrapped_key,
            rotation_config_sealed_data: model.rotation_config_sealed_data,
            rotation_config_wrapped_key: model.rotation_config_wrapped_key,
            execute_by,
        })
    }
}

/// Why [`WorkSnapshot::verify`] refused a claim. Carries no claim or blob values, only which
/// check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealRejection {
    /// Check 1: the target system's sealed data or wrapped key is absent.
    MissingTargetBlob,
    /// Check 1: the rotation config's sealed data or wrapped key is absent.
    MissingConfigBlob,
    /// The target system blob did not parse or unseal.
    TargetBlobInvalid,
    /// The rotation config blob did not parse or unseal.
    ConfigBlobInvalid,
    /// Check 2.
    TargetSystemIdMismatch,
    /// Check 3.
    CipherIdMismatch,
    /// Check 4.
    TargetMethodNotAutomatic,
    /// A legitimate `Automatic` target always seals a kind.
    /// Check 5.
    TargetKindMissing,
    /// Check 6.
    PolicyRejected,
}

impl SealRejection {
    /// A `'static` name, safe to report in logs and error details.
    pub fn as_str(self) -> &'static str {
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

/// A claim cross-checked by [`WorkSnapshot::verify`]; private fields keep it constructible only
/// there.
#[derive(Debug)]
pub struct VerifiedJob {
    attempt_id: Uuid,
    job_id: Uuid,
    target_system_id: Uuid,
    target_system_name: String,
    cipher_id: Uuid,
    kind: SealedTargetSystemKind,
    password_policy: SealedPasswordPolicy,
    account_identity: String,
    terminate_sessions: bool,
    execute_by: DateTime<Utc>,
}

impl VerifiedJob {
    /// The attempt every attempt-scoped request is keyed by.
    pub fn attempt_id(&self) -> Uuid {
        self.attempt_id
    }

    /// The rotation job.
    pub fn job_id(&self) -> Uuid {
        self.job_id
    }

    /// The target system, matching both sealed blobs.
    pub fn target_system_id(&self) -> Uuid {
        self.target_system_id
    }

    /// For logging only.
    pub fn target_system_name(&self) -> &str {
        &self.target_system_name
    }

    /// The cipher to rotate, matching the sealed config.
    pub fn cipher_id(&self) -> Uuid {
        self.cipher_id
    }

    /// The target-system kind, from the sealed blob only.
    pub fn kind(&self) -> SealedTargetSystemKind {
        self.kind
    }

    /// The sealed password policy, validated by check 6.
    pub fn password_policy(&self) -> &SealedPasswordPolicy {
        &self.password_policy
    }

    /// Passed verbatim to integrations, which must treat it as untrusted input.
    pub fn account_identity(&self) -> &str {
        &self.account_identity
    }

    /// Whether to terminate sessions, ANDed with the target's support.
    pub fn terminate_sessions(&self) -> bool {
        self.terminate_sessions
    }

    /// No target-side step starts after this.
    pub fn execute_by(&self) -> DateTime<Utc> {
        self.execute_by
    }

    /// Convert the sealed password policy into a [`PasswordGeneratorRequest`] of length
    /// `max_length`.
    ///
    /// Re-validates although [`WorkSnapshot::verify`] already did, so any call site that skips it
    /// fails closed.
    pub fn generator_request(&self) -> Result<PasswordGeneratorRequest, PasswordPolicyError> {
        let policy = &self.password_policy;
        policy.validate()?;

        let length = policy
            .max_length
            .clamp(GENERATOR_MIN_LENGTH, GENERATOR_MAX_LENGTH);

        // The generator's maximum length fits in a u8.
        #[allow(clippy::cast_possible_truncation)]
        let length_u8 = length as u8;

        Ok(PasswordGeneratorRequest {
            lowercase: policy.include_lowercase,
            uppercase: policy.include_uppercase,
            numbers: policy.include_digits,
            special: policy.include_symbols,
            length: length_u8,
            avoid_ambiguous: false,
            min_lowercase: None,
            min_uppercase: None,
            min_number: None,
            min_special: None,
            custom_required_chars: None,
            custom_allowed_chars: None,
            max_consecutive: None,
        })
    }
}

impl WorkSnapshot {
    /// Runs checks 1–7 on a claim, rejecting it with a [`SealRejection`] on the first failure.
    pub fn verify(
        self,
        key_store: &KeyStore<KeySlotIds>,
        organization_id: OrganizationId,
    ) -> Result<VerifiedJob, SealRejection> {
        // Check 1: both halves of each sealed value must be present and parse.
        let (target_envelope, target_key) = self
            .target_system_sealed_data
            .as_deref()
            .zip(self.target_system_wrapped_key.as_deref())
            .ok_or(SealRejection::MissingTargetBlob)?;
        let (config_envelope, config_key) = self
            .rotation_config_sealed_data
            .as_deref()
            .zip(self.rotation_config_wrapped_key.as_deref())
            .ok_or(SealRejection::MissingConfigBlob)?;

        let target_envelope: DataEnvelope = target_envelope
            .parse()
            .map_err(|_| SealRejection::TargetBlobInvalid)?;
        let config_envelope: DataEnvelope = config_envelope
            .parse()
            .map_err(|_| SealRejection::ConfigBlobInvalid)?;

        let mut ctx = key_store.context_mut();
        let org_slot = SymmetricKeySlotId::Organization(organization_id);

        let target: TargetSystemSealedV1 = unseal_target_system::<KeySlotIds>(
            &target_envelope,
            &EncString::from(target_key),
            &org_slot,
            &mut ctx,
        )
        .map_err(|_| SealRejection::TargetBlobInvalid)?;

        let config: RotationConfigSealedV1 = unseal_rotation_config::<KeySlotIds>(
            &config_envelope,
            &EncString::from(config_key),
            &org_slot,
            &mut ctx,
        )
        .map_err(|_| SealRejection::ConfigBlobInvalid)?;

        // Check 2.
        if self.target_system_id != target.target_system_id
            || self.target_system_id != config.target_system_id
        {
            return Err(SealRejection::TargetSystemIdMismatch);
        }

        // Check 3.
        if self.cipher_id != config.cipher_id {
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
            attempt_id: self.attempt_id,
            job_id: self.job_id,
            target_system_id: self.target_system_id,
            target_system_name: self.target_system_name,
            cipher_id: self.cipher_id,
            kind,
            password_policy: target.password_policy,
            account_identity: config.account_identity,
            terminate_sessions,
            execute_by: self.execute_by,
        })
    }
}

/// Fixture builders for the tests below.
#[cfg(test)]
mod test_support {
    use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};
    use bitwarden_pam_sealed::Sealed;

    use super::*;

    pub(super) fn test_org_id() -> OrganizationId {
        "3f1a5c4e-7b2d-4f8a-9c6e-1d2b3a4c5d6e"
            .parse()
            .expect("valid uuid")
    }

    pub(super) fn test_org_slot() -> SymmetricKeySlotId {
        SymmetricKeySlotId::Organization(test_org_id())
    }

    /// `(sealedData, wrappedKey)` as sent over the wire.
    pub(super) type SealedStrings = (String, String);

    /// A key store holding a fresh organization key, which is also returned.
    pub(super) fn store_with_org_key() -> (KeyStore<KeySlotIds>, SymmetricCryptoKey) {
        let store = KeyStore::default();
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        #[allow(deprecated)]
        store
            .context_mut()
            .set_symmetric_key(test_org_slot(), org_key.clone())
            .expect("set_symmetric_key");
        (store, org_key)
    }

    pub(super) fn strong_policy() -> SealedPasswordPolicy {
        SealedPasswordPolicy {
            min_length: 20,
            max_length: 20,
            include_uppercase: true,
            include_lowercase: true,
            include_digits: true,
            include_symbols: true,
        }
    }

    pub(super) fn sample_target(target_system_id: Uuid) -> TargetSystemSealedV1 {
        TargetSystemSealedV1 {
            target_system_id,
            method: SealedTargetSystemMethod::Automatic,
            kind: Some(bitwarden_pam_sealed::SealedTargetSystemKind::CustomScript),
            password_policy: strong_policy(),
            supports_session_termination: Some(true),
        }
    }

    pub(super) fn sample_config(target_system_id: Uuid, cipher_id: Uuid) -> RotationConfigSealedV1 {
        RotationConfigSealedV1 {
            target_system_id,
            cipher_id,
            account_identity: "svc-rotation@example.com".to_owned(),
            terminate_sessions: true,
        }
    }

    pub(super) fn work_snapshot(
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

    pub(super) fn sealed_pair(
        store: &KeyStore<KeySlotIds>,
        target: TargetSystemSealedV1,
        config: RotationConfigSealedV1,
    ) -> (SealedStrings, SealedStrings) {
        let mut ctx = store.context_mut();
        let target_blob = bitwarden_pam_sealed::seal_target_system::<KeySlotIds>(
            target,
            &test_org_slot(),
            &mut ctx,
        )
        .expect("seal target");
        let config_blob = bitwarden_pam_sealed::seal_rotation_config::<KeySlotIds>(
            config,
            &test_org_slot(),
            &mut ctx,
        )
        .expect("seal config");
        (strings(target_blob), strings(config_blob))
    }

    /// Wire form of a [`Sealed`]: `(sealedData, wrappedKey)`.
    pub(super) fn strings(sealed: Sealed) -> SealedStrings {
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

        let job = snapshot
            .verify(&store, test_org_id())
            .expect("well-formed claim should verify");

        assert_eq!(job.attempt_id(), attempt_id);
        assert_eq!(job.job_id(), job_id);
        assert_eq!(job.target_system_id(), target_system_id);
        assert_eq!(job.cipher_id(), cipher_id);
        assert_eq!(job.kind(), SealedTargetSystemKind::CustomScript);
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
            snapshot.verify(&store, test_org_id()).unwrap_err(),
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
            snapshot.verify(&store, test_org_id()).unwrap_err(),
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
            snapshot.verify(&store, test_org_id()).unwrap_err(),
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
            snapshot.verify(&store, test_org_id()).unwrap_err(),
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
            snapshot.verify(&store, test_org_id()).unwrap_err(),
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
            snapshot.verify(&store, test_org_id()).unwrap_err(),
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
            snapshot.verify(&store, test_org_id()).unwrap_err(),
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
                seal_target_system::<KeySlotIds>(
                    sample_target(target_system_id),
                    &test_org_slot(),
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
            snapshot.verify(&store, test_org_id()).unwrap_err(),
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
                seal_rotation_config::<KeySlotIds>(
                    sample_config(target_system_id, other_cipher_id),
                    &test_org_slot(),
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
            snapshot.verify(&store, test_org_id()).unwrap_err(),
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
                seal_target_system::<KeySlotIds>(
                    sample_target(other_target_id),
                    &test_org_slot(),
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
            snapshot.verify(&store, test_org_id()).unwrap_err(),
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
            snapshot.verify(&store, test_org_id()).unwrap_err(),
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
            snapshot.verify(&store, test_org_id()).unwrap_err(),
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
            snapshot.verify(&store, test_org_id()).unwrap_err(),
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
            snapshot.verify(&store, test_org_id()).unwrap_err(),
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
            snapshot.verify(&store, test_org_id()).unwrap_err(),
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

        let job = snapshot
            .verify(&store, test_org_id())
            .expect("an unsupported termination request must not be a rejection");
        assert!(!job.terminate_sessions());
    }
}

#[cfg(test)]
mod generator_request_tests {
    use bitwarden_core::Client;
    use bitwarden_generators::GeneratorClientsExt as _;

    use super::*;

    fn to_generator_request(
        policy: &SealedPasswordPolicy,
    ) -> Result<PasswordGeneratorRequest, PasswordPolicyError> {
        VerifiedJob {
            attempt_id: Uuid::new_v4(),
            job_id: Uuid::new_v4(),
            target_system_id: Uuid::new_v4(),
            target_system_name: "test-system".to_owned(),
            cipher_id: Uuid::new_v4(),
            kind: SealedTargetSystemKind::CustomScript,
            password_policy: policy.clone(),
            account_identity: "svc-rotation@example.com".to_owned(),
            terminate_sessions: false,
            execute_by: Utc::now(),
        }
        .generator_request()
    }

    fn all_classes(min_length: u32, max_length: u32) -> SealedPasswordPolicy {
        SealedPasswordPolicy {
            min_length,
            max_length,
            include_uppercase: true,
            include_lowercase: true,
            include_digits: true,
            include_symbols: true,
        }
    }

    fn password(
        req: PasswordGeneratorRequest,
    ) -> Result<String, bitwarden_generators::PasswordError> {
        Client::new(None).generator().password(req)
    }

    #[test]
    fn valid_policy_converts_length_from_max_length() {
        let req = to_generator_request(&all_classes(5, 20)).unwrap();
        assert_eq!(req.length, 20);
    }

    #[test]
    fn min_length_equal_max_length_is_valid() {
        let req = to_generator_request(&all_classes(16, 16)).unwrap();
        assert_eq!(req.length, 16);
    }

    #[test]
    fn max_length_at_generator_ceiling_is_valid() {
        let req = to_generator_request(&all_classes(5, GENERATOR_MAX_LENGTH)).unwrap();
        assert_eq!(u32::from(req.length), GENERATOR_MAX_LENGTH);
    }

    #[test]
    fn min_length_at_generator_floor_is_valid() {
        let req =
            to_generator_request(&all_classes(GENERATOR_MIN_LENGTH, GENERATOR_MIN_LENGTH)).unwrap();
        assert_eq!(u32::from(req.length), GENERATOR_MIN_LENGTH);
    }

    #[test]
    fn min_greater_than_max_is_rejected() {
        let err = to_generator_request(&all_classes(30, 20)).unwrap_err();
        assert_eq!(err, PasswordPolicyError::InvalidLengthBounds);
    }

    #[test]
    fn max_length_above_generator_ceiling_is_rejected() {
        let err = to_generator_request(&all_classes(5, GENERATOR_MAX_LENGTH + 1)).unwrap_err();
        assert_eq!(err, PasswordPolicyError::InvalidLengthBounds);
    }

    #[test]
    fn min_length_below_generator_floor_is_rejected() {
        let err = to_generator_request(&all_classes(GENERATOR_MIN_LENGTH - 1, 20)).unwrap_err();
        assert_eq!(err, PasswordPolicyError::InvalidLengthBounds);
    }

    #[test]
    fn no_character_classes_is_rejected() {
        let policy = SealedPasswordPolicy {
            min_length: GENERATOR_MIN_LENGTH,
            max_length: 20,
            include_uppercase: false,
            include_lowercase: false,
            include_digits: false,
            include_symbols: false,
        };
        let err = to_generator_request(&policy).unwrap_err();
        assert_eq!(err, PasswordPolicyError::NoCharacterClasses);
    }

    #[test]
    fn single_class_enabled_is_sufficient() {
        for (upper, lower, digits, symbols) in [
            (true, false, false, false),
            (false, true, false, false),
            (false, false, true, false),
            (false, false, false, true),
        ] {
            let policy = SealedPasswordPolicy {
                min_length: 30,
                max_length: 30,
                include_uppercase: upper,
                include_lowercase: lower,
                include_digits: digits,
                include_symbols: symbols,
            };
            assert!(
                to_generator_request(&policy).is_ok(),
                "expected Ok for a single enabled class at length 30: \
                 upper={upper} lower={lower} digits={digits} symbols={symbols}"
            );
        }
    }

    #[test]
    fn include_flags_map_correctly() {
        let policy = SealedPasswordPolicy {
            min_length: 30,
            max_length: 30,
            include_uppercase: true,
            include_lowercase: false,
            include_digits: true,
            include_symbols: false,
        };
        let req = to_generator_request(&policy).unwrap();
        assert!(req.uppercase);
        assert!(!req.lowercase);
        assert!(req.numbers);
        assert!(!req.special);
        assert!(req.min_uppercase.is_none());
        assert!(req.min_lowercase.is_none());
        assert!(req.min_number.is_none());
        assert!(req.min_special.is_none());
        assert!(!req.avoid_ambiguous);
        assert!(req.custom_required_chars.is_none());
        assert!(req.custom_allowed_chars.is_none());
        assert!(req.max_consecutive.is_none());
    }

    #[test]
    fn generated_request_produces_valid_password() {
        let req = to_generator_request(&all_classes(14, 32)).unwrap();
        let result = password(req);
        assert!(result.is_ok(), "expected password() to succeed: {result:?}");
        let pwd = result.unwrap();
        assert!(
            pwd.len() >= 5 && pwd.len() <= 128,
            "password length {len} out of expected range",
            len = pwd.len()
        );
    }

    #[test]
    fn generated_password_uses_only_enabled_charset() {
        let policy = SealedPasswordPolicy {
            min_length: 30,
            max_length: 30,
            include_uppercase: false,
            include_lowercase: false,
            include_digits: true,
            include_symbols: false,
        };
        let req = to_generator_request(&policy).unwrap();
        assert_eq!(req.length, 30);
        let pwd = password(req).unwrap();
        assert!(
            pwd.chars().all(|c| c.is_ascii_digit()),
            "expected only digits in {pwd:?}"
        );
    }

    #[test]
    fn generated_password_at_maximum_length() {
        let req = to_generator_request(&all_classes(5, GENERATOR_MAX_LENGTH)).unwrap();
        assert_eq!(u32::from(req.length), GENERATOR_MAX_LENGTH);
        let pwd = password(req).unwrap();
        assert_eq!(pwd.len() as u32, GENERATOR_MAX_LENGTH);
    }
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    fn claim() -> RotationClaimResponseModel {
        RotationClaimResponseModel {
            attempt_id: Some(Uuid::new_v4()),
            job_id: Some(Uuid::new_v4()),
            source: None,
            target_system_id: Some(Uuid::new_v4()),
            target_system_name: Some("test-system".to_owned()),
            target_system_sealed_data: Some("opaque-target-blob".to_owned()),
            target_system_wrapped_key: Some("opaque-target-key".to_owned()),
            cipher_id: Some(Uuid::new_v4()),
            rotation_config_sealed_data: Some("opaque-config-blob".to_owned()),
            rotation_config_wrapped_key: Some("opaque-config-key".to_owned()),
            execute_by: Some(Utc::now().to_rfc3339()),
        }
    }

    #[test]
    fn converts_correctly() {
        let snap = WorkSnapshot::try_from(claim()).expect("parse");
        assert_eq!(
            snap.target_system_sealed_data.as_deref(),
            Some("opaque-target-blob")
        );
        assert_eq!(
            snap.target_system_wrapped_key.as_deref(),
            Some("opaque-target-key")
        );
        assert_eq!(
            snap.rotation_config_sealed_data.as_deref(),
            Some("opaque-config-blob")
        );
        assert_eq!(
            snap.rotation_config_wrapped_key.as_deref(),
            Some("opaque-config-key")
        );
    }

    #[test]
    fn missing_sealed_blobs_still_parses() {
        let model = RotationClaimResponseModel {
            target_system_sealed_data: None,
            target_system_wrapped_key: None,
            rotation_config_sealed_data: None,
            rotation_config_wrapped_key: None,
            ..claim()
        };

        let snap = WorkSnapshot::try_from(model).expect("parse");
        assert!(snap.target_system_sealed_data.is_none());
        assert!(snap.target_system_wrapped_key.is_none());
        assert!(snap.rotation_config_sealed_data.is_none());
        assert!(snap.rotation_config_wrapped_key.is_none());
    }

    #[test]
    fn missing_field_is_an_error() {
        let err = WorkSnapshot::try_from(RotationClaimResponseModel::new()).expect_err("fails");
        assert!(matches!(err, WorkSnapshotError::MissingField(_)));
    }

    #[test]
    fn bad_execute_by_is_an_error() {
        let model = RotationClaimResponseModel {
            execute_by: Some("NOT-A-DATE".to_owned()),
            ..claim()
        };

        let err = WorkSnapshot::try_from(model).expect_err("fails");
        assert!(matches!(err, WorkSnapshotError::InvalidExecuteBy));
    }
}
