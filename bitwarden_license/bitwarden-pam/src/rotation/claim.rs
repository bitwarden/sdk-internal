//! A claimed rotation job and its verification.
//!
//! [`WorkSnapshot::verify`] cross-checks a claim's two sealed values against each other and the
//! plaintext claim. The pre-flight cipher read needs the network, so the access connector does it.
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
    /// The target system's sealed data or wrapped key is absent.
    MissingTargetBlob,
    /// The rotation config's sealed data or wrapped key is absent.
    MissingConfigBlob,
    /// The target system blob did not parse or unseal.
    TargetBlobInvalid,
    /// The rotation config blob did not parse or unseal.
    ConfigBlobInvalid,
    /// The claimed target system differs from one of the sealed blobs.
    TargetSystemIdMismatch,
    /// The claimed cipher differs from the sealed config.
    CipherIdMismatch,
    /// The sealed target system is not set to automatic rotation.
    TargetMethodNotAutomatic,
    /// The sealed target system has no kind, which an `Automatic` target always seals.
    TargetKindMissing,
    /// The sealed password policy is invalid.
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

    /// The sealed password policy, already validated.
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

    /// Converts the sealed password policy into a [`PasswordGeneratorRequest`] of length
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
    /// Cross-checks the claim against its sealed values, rejecting it with a [`SealRejection`] on
    /// the first failure.
    pub fn verify(
        self,
        key_store: &KeyStore<KeySlotIds>,
        organization_id: OrganizationId,
    ) -> Result<VerifiedJob, SealRejection> {
        // Both halves of each sealed value must be present and parse.
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

        if self.target_system_id != target.target_system_id
            || self.target_system_id != config.target_system_id
        {
            return Err(SealRejection::TargetSystemIdMismatch);
        }

        if self.cipher_id != config.cipher_id {
            return Err(SealRejection::CipherIdMismatch);
        }

        // Trust only the sealed method; the server's plaintext copy is advisory.
        if target.method != SealedTargetSystemMethod::Automatic {
            return Err(SealRejection::TargetMethodNotAutomatic);
        }

        // Kind, policy and account identity come from the blobs only.
        let kind = target.kind.ok_or(SealRejection::TargetKindMissing)?;

        target
            .password_policy
            .validate()
            .map_err(|_| SealRejection::PolicyRejected)?;

        // Unsupported termination is ANDed to false, not a rejection.
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
    use bitwarden_pam_sealed::{Sealed, seal_rotation_config, seal_target_system};

    use super::*;

    /// `(sealedData, wrappedKey)` as sent over the wire.
    pub(super) type SealedStrings = (String, String);

    fn org_id() -> OrganizationId {
        "3f1a5c4e-7b2d-4f8a-9c6e-1d2b3a4c5d6e"
            .parse()
            .expect("valid uuid")
    }

    fn org_slot() -> SymmetricKeySlotId {
        SymmetricKeySlotId::Organization(org_id())
    }

    /// Wire form of a [`Sealed`].
    fn strings(sealed: Sealed) -> SealedStrings {
        (sealed.envelope.to_string(), sealed.wrapped_key.to_string())
    }

    pub(super) fn all_classes(min_length: u32, max_length: u32) -> SealedPasswordPolicy {
        SealedPasswordPolicy {
            min_length,
            max_length,
            include_uppercase: true,
            include_lowercase: true,
            include_digits: true,
            include_symbols: true,
        }
    }

    pub(super) fn no_classes() -> SealedPasswordPolicy {
        SealedPasswordPolicy {
            include_uppercase: false,
            include_lowercase: false,
            include_digits: false,
            include_symbols: false,
            ..all_classes(20, 20)
        }
    }

    /// A key store holding a fresh organization key, and the IDs a well-formed claim agrees on.
    pub(super) struct Fixture {
        store: KeyStore<KeySlotIds>,
        pub(super) target_system_id: Uuid,
        pub(super) cipher_id: Uuid,
    }

    impl Fixture {
        pub(super) fn new() -> Self {
            let store = KeyStore::default();
            #[allow(deprecated)]
            store
                .context_mut()
                .set_symmetric_key(
                    org_slot(),
                    SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac),
                )
                .expect("set_symmetric_key");
            Self {
                store,
                target_system_id: Uuid::new_v4(),
                cipher_id: Uuid::new_v4(),
            }
        }

        pub(super) fn target(&self) -> TargetSystemSealedV1 {
            TargetSystemSealedV1 {
                target_system_id: self.target_system_id,
                method: SealedTargetSystemMethod::Automatic,
                kind: Some(SealedTargetSystemKind::CustomScript),
                password_policy: all_classes(20, 20),
                supports_session_termination: Some(true),
            }
        }

        pub(super) fn config(&self) -> RotationConfigSealedV1 {
            RotationConfigSealedV1 {
                target_system_id: self.target_system_id,
                cipher_id: self.cipher_id,
                account_identity: "svc-rotation@example.com".to_owned(),
                terminate_sessions: true,
            }
        }

        pub(super) fn seal_target(&self, target: TargetSystemSealedV1) -> SealedStrings {
            let mut ctx = self.store.context_mut();
            strings(seal_target_system::<KeySlotIds>(target, &org_slot(), &mut ctx).expect("seal"))
        }

        pub(super) fn seal_config(&self, config: RotationConfigSealedV1) -> SealedStrings {
            let mut ctx = self.store.context_mut();
            strings(
                seal_rotation_config::<KeySlotIds>(config, &org_slot(), &mut ctx).expect("seal"),
            )
        }

        /// A claim carrying the fixture's IDs and the given blobs.
        pub(super) fn snapshot(
            &self,
            target_blob: Option<SealedStrings>,
            config_blob: Option<SealedStrings>,
        ) -> WorkSnapshot {
            let (target_data, target_key) = target_blob.unzip();
            let (config_data, config_key) = config_blob.unzip();
            WorkSnapshot {
                attempt_id: Uuid::new_v4(),
                job_id: Uuid::new_v4(),
                target_system_id: self.target_system_id,
                target_system_name: "test-system".to_owned(),
                cipher_id: self.cipher_id,
                target_system_sealed_data: target_data,
                target_system_wrapped_key: target_key,
                rotation_config_sealed_data: config_data,
                rotation_config_wrapped_key: config_key,
                execute_by: Utc::now() + chrono::Duration::minutes(5),
            }
        }

        /// A claim carrying `target` and `config`, both sealed under the fixture's org key.
        pub(super) fn sealed_snapshot(
            &self,
            target: TargetSystemSealedV1,
            config: RotationConfigSealedV1,
        ) -> WorkSnapshot {
            self.snapshot(
                Some(self.seal_target(target)),
                Some(self.seal_config(config)),
            )
        }

        /// A claim that passes every check.
        pub(super) fn valid_snapshot(&self) -> WorkSnapshot {
            self.sealed_snapshot(self.target(), self.config())
        }

        pub(super) fn verify(&self, snapshot: WorkSnapshot) -> Result<VerifiedJob, SealRejection> {
            snapshot.verify(&self.store, org_id())
        }

        pub(super) fn reject(&self, snapshot: WorkSnapshot) -> SealRejection {
            self.verify(snapshot).expect_err("claim should be rejected")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{test_support::*, *};

    #[test]
    fn happy_path_produces_verified_job() {
        let f = Fixture::new();
        let snapshot = f.valid_snapshot();
        let (attempt_id, job_id) = (snapshot.attempt_id, snapshot.job_id);

        let job = f.verify(snapshot).expect("well-formed claim should verify");

        assert_eq!(job.attempt_id(), attempt_id);
        assert_eq!(job.job_id(), job_id);
        assert_eq!(job.target_system_id(), f.target_system_id);
        assert_eq!(job.cipher_id(), f.cipher_id);
        assert_eq!(job.kind(), SealedTargetSystemKind::CustomScript);
        assert_eq!(job.account_identity(), "svc-rotation@example.com");
        assert!(job.terminate_sessions());
    }

    #[test]
    fn missing_target_blob_is_rejected() {
        let f = Fixture::new();
        let snapshot = f.snapshot(None, Some(f.seal_config(f.config())));
        assert_eq!(f.reject(snapshot), SealRejection::MissingTargetBlob);
    }

    #[test]
    fn missing_config_blob_is_rejected() {
        let f = Fixture::new();
        let snapshot = f.snapshot(Some(f.seal_target(f.target())), None);
        assert_eq!(f.reject(snapshot), SealRejection::MissingConfigBlob);
    }

    #[test]
    fn target_sealed_data_without_wrapped_key_is_rejected() {
        let f = Fixture::new();
        let mut snapshot = f.valid_snapshot();
        snapshot.target_system_wrapped_key = None;
        assert_eq!(f.reject(snapshot), SealRejection::MissingTargetBlob);
    }

    #[test]
    fn config_sealed_data_without_wrapped_key_is_rejected() {
        let f = Fixture::new();
        let mut snapshot = f.valid_snapshot();
        snapshot.rotation_config_wrapped_key = None;
        assert_eq!(f.reject(snapshot), SealRejection::MissingConfigBlob);
    }

    #[test]
    fn unparseable_wrapped_key_is_rejected() {
        let f = Fixture::new();
        let mut snapshot = f.valid_snapshot();
        snapshot.target_system_wrapped_key = Some("not a wrapped key".to_owned());
        assert_eq!(f.reject(snapshot), SealRejection::TargetBlobInvalid);
    }

    #[test]
    fn wrapped_key_from_a_different_seal_is_rejected() {
        // Envelope from one seal, wrapped key from another: the key does not open the envelope.
        let f = Fixture::new();
        let (_, other_key) = f.seal_target(f.target());
        let mut snapshot = f.valid_snapshot();
        snapshot.target_system_wrapped_key = Some(other_key);
        assert_eq!(f.reject(snapshot), SealRejection::TargetBlobInvalid);
    }

    #[test]
    fn garbage_target_blob_is_rejected() {
        let f = Fixture::new();
        let mut snapshot = f.valid_snapshot();
        snapshot.target_system_sealed_data = Some("not a sealed blob".to_owned());
        assert_eq!(f.reject(snapshot), SealRejection::TargetBlobInvalid);
    }

    #[test]
    fn target_blob_sealed_under_a_different_org_key_is_rejected() {
        let f = Fixture::new();
        let other_key = Fixture::new();
        let snapshot = f.snapshot(
            Some(other_key.seal_target(f.target())),
            Some(f.seal_config(f.config())),
        );
        assert_eq!(f.reject(snapshot), SealRejection::TargetBlobInvalid);
    }

    #[test]
    fn config_blob_from_a_different_config_is_rejected() {
        // A config swapped in from another rotation config: same target, different cipher.
        let f = Fixture::new();
        let other_config = RotationConfigSealedV1 {
            cipher_id: Uuid::new_v4(),
            ..f.config()
        };
        let snapshot = f.sealed_snapshot(f.target(), other_config);
        assert_eq!(f.reject(snapshot), SealRejection::CipherIdMismatch);
    }

    #[test]
    fn target_blob_from_a_different_target_is_rejected() {
        let f = Fixture::new();
        let other_target = TargetSystemSealedV1 {
            target_system_id: Uuid::new_v4(),
            ..f.target()
        };
        let snapshot = f.sealed_snapshot(other_target, f.config());
        assert_eq!(f.reject(snapshot), SealRejection::TargetSystemIdMismatch);
    }

    #[test]
    fn claim_target_id_differs_from_sealed_blobs_is_rejected() {
        let f = Fixture::new();
        let mut snapshot = f.valid_snapshot();
        snapshot.target_system_id = Uuid::new_v4();
        assert_eq!(f.reject(snapshot), SealRejection::TargetSystemIdMismatch);
    }

    #[test]
    fn claim_cipher_id_differs_from_config_blob_is_rejected() {
        let f = Fixture::new();
        let mut snapshot = f.valid_snapshot();
        snapshot.cipher_id = Uuid::new_v4();
        assert_eq!(f.reject(snapshot), SealRejection::CipherIdMismatch);
    }

    #[test]
    fn manual_target_method_is_rejected() {
        let f = Fixture::new();
        let manual_target = TargetSystemSealedV1 {
            method: SealedTargetSystemMethod::Manual,
            kind: None,
            supports_session_termination: None,
            ..f.target()
        };
        let snapshot = f.sealed_snapshot(manual_target, f.config());
        assert_eq!(f.reject(snapshot), SealRejection::TargetMethodNotAutomatic);
    }

    #[test]
    fn automatic_target_with_missing_kind_is_rejected() {
        let f = Fixture::new();
        let malformed_target = TargetSystemSealedV1 {
            kind: None,
            ..f.target()
        };
        let snapshot = f.sealed_snapshot(malformed_target, f.config());
        assert_eq!(f.reject(snapshot), SealRejection::TargetKindMissing);
    }

    #[test]
    fn policy_with_no_character_classes_is_rejected() {
        let f = Fixture::new();
        let invalid_target = TargetSystemSealedV1 {
            password_policy: no_classes(),
            ..f.target()
        };
        let snapshot = f.sealed_snapshot(invalid_target, f.config());
        assert_eq!(f.reject(snapshot), SealRejection::PolicyRejected);
    }

    #[test]
    fn terminate_requested_but_unsupported_is_anded_to_false_not_rejected() {
        let f = Fixture::new();
        let target = TargetSystemSealedV1 {
            supports_session_termination: Some(false),
            ..f.target()
        };
        let config = RotationConfigSealedV1 {
            terminate_sessions: true,
            ..f.config()
        };

        let job = f
            .verify(f.sealed_snapshot(target, config))
            .expect("an unsupported termination request must not be a rejection");
        assert!(!job.terminate_sessions());
    }
}

#[cfg(test)]
mod generator_request_tests {
    use bitwarden_core::Client;
    use bitwarden_generators::GeneratorClientsExt as _;

    use super::{test_support::*, *};

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

    fn password(req: PasswordGeneratorRequest) -> String {
        Client::new(None)
            .generator()
            .password(req)
            .expect("generate password")
    }

    #[test]
    fn length_is_taken_from_max_length() {
        for (min, max) in [
            (5, 20),
            (16, 16),
            (5, GENERATOR_MAX_LENGTH),
            (GENERATOR_MIN_LENGTH, GENERATOR_MIN_LENGTH),
        ] {
            let req = to_generator_request(&all_classes(min, max)).unwrap();
            assert_eq!(u32::from(req.length), max, "min={min} max={max}");
        }
    }

    #[test]
    fn out_of_range_lengths_are_rejected() {
        for (min, max) in [
            (30, 20),
            (5, GENERATOR_MAX_LENGTH + 1),
            (GENERATOR_MIN_LENGTH - 1, 20),
        ] {
            assert_eq!(
                to_generator_request(&all_classes(min, max)).unwrap_err(),
                PasswordPolicyError::InvalidLengthBounds,
                "min={min} max={max}"
            );
        }
    }

    #[test]
    fn no_character_classes_is_rejected() {
        let err = to_generator_request(&no_classes()).unwrap_err();
        assert_eq!(err, PasswordPolicyError::NoCharacterClasses);
    }

    #[test]
    fn single_class_enabled_is_sufficient() {
        for policy in [
            SealedPasswordPolicy {
                include_uppercase: true,
                ..no_classes()
            },
            SealedPasswordPolicy {
                include_lowercase: true,
                ..no_classes()
            },
            SealedPasswordPolicy {
                include_digits: true,
                ..no_classes()
            },
            SealedPasswordPolicy {
                include_symbols: true,
                ..no_classes()
            },
        ] {
            assert!(to_generator_request(&policy).is_ok(), "{policy:?}");
        }
    }

    #[test]
    fn include_flags_map_correctly() {
        let policy = SealedPasswordPolicy {
            include_lowercase: false,
            include_symbols: false,
            ..all_classes(30, 30)
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
    fn generated_password_uses_only_enabled_charset() {
        let policy = SealedPasswordPolicy {
            include_digits: true,
            ..no_classes()
        };
        let pwd = password(to_generator_request(&policy).unwrap());
        assert!(
            pwd.chars().all(|c| c.is_ascii_digit()),
            "expected only digits in {pwd:?}"
        );
    }

    #[test]
    fn generated_password_at_maximum_length() {
        let req = to_generator_request(&all_classes(5, GENERATOR_MAX_LENGTH)).unwrap();
        let pwd = password(req);
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
