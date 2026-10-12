use bitwarden_pam_sealed::{PolicyStrengthError, SealedPasswordPolicy};
use thiserror::Error;

use super::{
    configs::RotationConfigCreateRequest, models::PasswordPolicy, schedule::is_likely_quartz_cron,
    target_systems::TargetSystemCreateRequest,
};

/// Maximum length of a connector or target-system `name`, matching the server's column.
const MAX_NAME_LENGTH: usize = 200;
/// Maximum length of a config's `account_identity`, matching the server's column.
const MAX_ACCOUNT_IDENTITY_LENGTH: usize = 500;

/// Errors from validating a rotation request before it is sent to the server.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RotationValidationError {
    /// A `name` was empty (after trimming) or exceeded the server's length limit.
    #[error("Name must be between 1 and {MAX_NAME_LENGTH} characters")]
    InvalidName,
    /// `account_identity` was empty (after trimming) or exceeded the server's length limit.
    #[error("Account identity must be between 1 and {MAX_ACCOUNT_IDENTITY_LENGTH} characters")]
    InvalidAccountIdentity,
    /// A password policy's length bounds were outside the generator's supported range
    /// (`bitwarden_pam_sealed::GENERATOR_MIN_LENGTH`..
    /// =`bitwarden_pam_sealed::GENERATOR_MAX_LENGTH`), or `min_length` exceeded `max_length`.
    #[error("Password length bounds are outside the generator's supported range")]
    InvalidPasswordLengthBounds,
    /// A password policy enabled no character classes, so no credential could satisfy it.
    #[error("A password policy must allow at least one character class")]
    NoCharacterClasses,
    /// A password policy's generated password would fall below the shared strength floor
    /// (`bitwarden_pam_sealed::MIN_PASSWORD_ENTROPY_BITS`). The blobs stop a hostile server
    /// changing a policy in transit, but not replaying an old weak one, so both this client and
    /// the access connector enforce the same floor independently.
    #[error("Password policy falls below the minimum password strength floor")]
    BelowPasswordStrengthFloor,
    /// `schedule_cron` was present but is not shaped like a Quartz cron expression.
    #[error("Schedule must be a 6- or 7-field Quartz cron expression")]
    InvalidCron,
    /// `terminate_sessions` was requested, but the target system does not confirm it supports
    /// session termination: its unsealed `supports_session_termination` is not `Some(true)`. A
    /// `PendingSeal` or `Invalid` target's capability is unknown, which is treated the same as
    /// unsupported.
    #[error("The target system does not confirm it supports session termination")]
    SessionTerminationUnsupported,
    /// The rotation config's target system exists but its sealed blob is `Invalid` (missing,
    /// undecryptable, or mismatched), so nothing about it can be trusted.
    #[error("The target system's sealed data is invalid")]
    TargetSystemSealInvalid,
    /// [`TargetSystemsClient::update`](super::TargetSystemsClient::update)'s request named a
    /// different `method` than the target system's own plaintext `method`. Method is fixed at
    /// registration; nothing lets a target switch between automatic and manual.
    #[error("Target system method cannot be changed")]
    TargetSystemMethodMismatch,
    /// [`TargetSystemsClient::update`](super::TargetSystemsClient::update)'s request named a
    /// different `kind` than the target system's own sealed `kind` (only checked once the
    /// existing blob's [`TargetSystemSealedFields`](crate::TargetSystemSealedFields) are
    /// confirmed present). Kind is fixed at registration; nothing lets a target switch
    /// integrations.
    #[error("Target system kind cannot be changed")]
    TargetSystemKindMismatch,
    /// [`RotationConfigsClient::update`](super::RotationConfigsClient::update)'s request named a
    /// different `cipher_id` or `target_system_id` than the config's own plaintext copies. Both
    /// are fixed at creation; nothing lets a config move to a different cipher or target.
    #[error("Rotation config cipher or target system cannot be changed")]
    RotationConfigImmutableFieldMismatch,
}

impl From<PolicyStrengthError> for RotationValidationError {
    fn from(error: PolicyStrengthError) -> Self {
        match error {
            PolicyStrengthError::NoCharacterClasses => Self::NoCharacterClasses,
            PolicyStrengthError::InvalidLengthBounds => Self::InvalidPasswordLengthBounds,
            PolicyStrengthError::BelowStrengthFloor => Self::BelowPasswordStrengthFloor,
        }
    }
}

/// Validates a name against the server's length limit, counted in UTF-16 code units as the
/// server's `nvarchar` column counts them.
pub(super) fn validate_name(name: &str) -> Result<(), RotationValidationError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.encode_utf16().count() > MAX_NAME_LENGTH {
        return Err(RotationValidationError::InvalidName);
    }

    Ok(())
}

fn validate_account_identity(identity: &str) -> Result<(), RotationValidationError> {
    let trimmed = identity.trim();
    if trimmed.is_empty() || trimmed.encode_utf16().count() > MAX_ACCOUNT_IDENTITY_LENGTH {
        return Err(RotationValidationError::InvalidAccountIdentity);
    }

    Ok(())
}

/// Validates a password policy against the shared `bitwarden-pam-sealed` strength floor: the
/// generator's supported length range plus a minimum entropy bound. Both this client and the
/// access connector enforce the same rule, so an operator learns about a weak policy while
/// editing rather than from a silently-clamped or refused rotation.
pub(super) fn validate_password_policy(
    policy: &PasswordPolicy,
) -> Result<(), RotationValidationError> {
    let sealed: SealedPasswordPolicy = policy.clone().try_into()?;
    sealed.validate()?;
    Ok(())
}

/// Validates a set cron expression; `None` means no schedule. Only the shape is checked, since the
/// server owns the minimum-interval floor.
fn validate_schedule_cron(cron: Option<&String>) -> Result<(), RotationValidationError> {
    match cron {
        Some(cron) if !is_likely_quartz_cron(cron) => Err(RotationValidationError::InvalidCron),
        _ => Ok(()),
    }
}

/// Validates a target system request. Shared by
/// [`TargetSystemsClient::create`](super::TargetSystemsClient::create) and
/// [`TargetSystemsClient::update`](super::TargetSystemsClient::update), which take the same
/// request shape — see [`TargetSystemsClient::update`](super::TargetSystemsClient::update)'s docs
/// for why.
pub(super) fn validate_target_system_request(
    request: &TargetSystemCreateRequest,
) -> Result<(), RotationValidationError> {
    validate_name(request.name())?;
    validate_password_policy(request.password_policy())
}

/// Validates a rotation config request. Shared by
/// [`RotationConfigsClient::create`](super::RotationConfigsClient::create) and
/// [`RotationConfigsClient::update`](super::RotationConfigsClient::update), which take the same
/// request shape — see [`RotationConfigsClient::update`](super::RotationConfigsClient::update)'s
/// docs for why. Does not validate `terminate_sessions` against the target system's capability;
/// that needs a network round trip and is done separately by the caller.
pub(super) fn validate_config_request(
    request: &RotationConfigCreateRequest,
) -> Result<(), RotationValidationError> {
    validate_account_identity(&request.account_identity)?;
    validate_schedule_cron(request.schedule_cron.as_ref())
}

#[cfg(test)]
mod tests {
    use bitwarden_pam_sealed::{GENERATOR_MAX_LENGTH, GENERATOR_MIN_LENGTH};
    use bitwarden_vault::CipherId;
    use uuid::uuid;

    use super::*;
    use crate::{TargetSystemId, rotation::models::TargetSystemKind};

    fn policy() -> PasswordPolicy {
        // 64 * log2(26+26+10+10) ~= 64 * 6.17 ~= 395 bits, comfortably above the 80-bit floor.
        PasswordPolicy {
            min_length: 14,
            max_length: 64,
            include_uppercase: true,
            include_lowercase: true,
            include_digits: true,
            include_symbols: true,
        }
    }

    fn create_request(name: &str) -> TargetSystemCreateRequest {
        TargetSystemCreateRequest::Automatic {
            name: name.to_string(),
            kind: TargetSystemKind::Entra,
            password_policy: policy(),
            supports_session_termination: true,
        }
    }

    fn config_create(account_identity: &str, cron: Option<&str>) -> RotationConfigCreateRequest {
        RotationConfigCreateRequest {
            cipher_id: CipherId::new(uuid!("11111111-1111-1111-1111-111111111111")),
            target_system_id: TargetSystemId::new(uuid!("22222222-2222-2222-2222-222222222222")),
            account_identity: account_identity.to_string(),
            terminate_sessions: false,
            schedule_cron: cron.map(ToString::to_string),
            rotate_on_access_end: false,
        }
    }

    #[test]
    fn a_well_formed_create_request_passes() {
        assert!(validate_target_system_request(&create_request("Prod SQL")).is_ok());
    }

    #[test]
    fn a_blank_name_is_rejected() {
        for name in ["", "   ", "\t\n"] {
            assert_eq!(
                validate_target_system_request(&create_request(name)),
                Err(RotationValidationError::InvalidName),
                "for {name:?}"
            );
        }
    }

    #[test]
    fn a_name_at_the_limit_passes_and_one_over_is_rejected() {
        let at_limit = "a".repeat(MAX_NAME_LENGTH);
        assert!(validate_target_system_request(&create_request(&at_limit)).is_ok());

        let over_limit = "a".repeat(MAX_NAME_LENGTH + 1);
        assert_eq!(
            validate_target_system_request(&create_request(&over_limit)),
            Err(RotationValidationError::InvalidName)
        );
    }

    /// An astral character costs two UTF-16 code units, so 100 of them fill the 200-unit limit and
    /// 101 overflow it; a `char` count would pass both.
    #[test]
    fn name_length_is_counted_in_utf16_code_units() {
        let at_limit = "😀".repeat(MAX_NAME_LENGTH / 2);
        assert!(validate_target_system_request(&create_request(&at_limit)).is_ok());

        let over_limit = "😀".repeat(MAX_NAME_LENGTH / 2 + 1);
        assert_eq!(
            validate_target_system_request(&create_request(&over_limit)),
            Err(RotationValidationError::InvalidName)
        );
    }

    /// Leading and trailing whitespace is trimmed before measuring, so padding cannot push a
    /// valid name over the limit.
    #[test]
    fn surrounding_whitespace_does_not_count_towards_the_limit() {
        let padded = format!("  {}  ", "a".repeat(MAX_NAME_LENGTH));
        assert!(validate_target_system_request(&create_request(&padded)).is_ok());
    }

    #[test]
    fn inverted_length_bounds_are_rejected() {
        let request = TargetSystemCreateRequest::Manual {
            name: "Manual".to_string(),
            password_policy: PasswordPolicy {
                min_length: 64,
                max_length: 14,
                ..policy()
            },
        };

        assert_eq!(
            validate_target_system_request(&request),
            Err(RotationValidationError::InvalidPasswordLengthBounds)
        );
    }

    /// Length bounds outside the generator's supported range are rejected, even when the bounds
    /// are correctly ordered.
    #[test]
    fn length_bounds_outside_the_generator_range_are_rejected() {
        let min = i32::try_from(GENERATOR_MIN_LENGTH).expect("fits in i32");
        let max = i32::try_from(GENERATOR_MAX_LENGTH).expect("fits in i32");

        for (min_length, max_length) in [(0, 64), (-1, 64), (14, max + 1), (min - 1, max)] {
            let request = TargetSystemCreateRequest::Manual {
                name: "Manual".to_string(),
                password_policy: PasswordPolicy {
                    min_length,
                    max_length,
                    ..policy()
                },
            };

            assert_eq!(
                validate_target_system_request(&request),
                Err(RotationValidationError::InvalidPasswordLengthBounds),
                "for {min_length}..{max_length}"
            );
        }
    }

    #[test]
    fn equal_length_bounds_are_accepted() {
        let request = TargetSystemCreateRequest::Manual {
            name: "Manual".to_string(),
            password_policy: PasswordPolicy {
                min_length: 32,
                max_length: 32,
                ..policy()
            },
        };

        assert!(validate_target_system_request(&request).is_ok());
    }

    /// A policy with every class off is unsatisfiable, and the connector's generator raises the
    /// same failure at rotation time.
    #[test]
    fn a_policy_with_no_character_classes_is_rejected() {
        let request = TargetSystemCreateRequest::Manual {
            name: "Manual".to_string(),
            password_policy: PasswordPolicy {
                include_uppercase: false,
                include_lowercase: false,
                include_digits: false,
                include_symbols: false,
                ..policy()
            },
        };

        assert_eq!(
            validate_target_system_request(&request),
            Err(RotationValidationError::NoCharacterClasses)
        );
    }

    #[test]
    fn a_single_character_class_is_enough() {
        let request = TargetSystemCreateRequest::Manual {
            name: "Manual".to_string(),
            password_policy: PasswordPolicy {
                include_uppercase: false,
                include_lowercase: true,
                include_digits: false,
                include_symbols: false,
                ..policy()
            },
        };

        assert!(validate_target_system_request(&request).is_ok());
    }

    /// The blobs stop a hostile server changing a policy in transit, but not replaying an old
    /// weak one, so the strength floor is enforced here too, not just length bounds.
    #[test]
    fn a_policy_below_the_strength_floor_is_rejected() {
        // 20 * log2(10) ~= 66.4 bits < 80.
        let weak = PasswordPolicy {
            min_length: i32::try_from(GENERATOR_MIN_LENGTH).expect("fits in i32"),
            max_length: 20,
            include_uppercase: false,
            include_lowercase: false,
            include_digits: true,
            include_symbols: false,
        };

        let request = TargetSystemCreateRequest::Manual {
            name: "Manual".to_string(),
            password_policy: weak,
        };

        assert_eq!(
            validate_target_system_request(&request),
            Err(RotationValidationError::BelowPasswordStrengthFloor)
        );
    }

    #[test]
    fn a_config_with_no_schedule_is_valid() {
        assert!(validate_config_request(&config_create("svc_rotation", None)).is_ok());
    }

    #[test]
    fn a_config_with_a_well_formed_cron_is_valid() {
        assert!(
            validate_config_request(&config_create("svc_rotation", Some("0 0 0 * * ?"))).is_ok()
        );
    }

    #[test]
    fn a_malformed_cron_is_rejected() {
        // A 5-field UNIX cron, the likeliest operator mistake.
        assert_eq!(
            validate_config_request(&config_create("svc_rotation", Some("0 0 * * *"))),
            Err(RotationValidationError::InvalidCron)
        );
    }

    #[test]
    fn a_blank_account_identity_is_rejected() {
        assert_eq!(
            validate_config_request(&config_create("   ", None)),
            Err(RotationValidationError::InvalidAccountIdentity)
        );
    }

    #[test]
    fn an_account_identity_at_the_limit_passes_and_one_over_is_rejected() {
        let at_limit = "a".repeat(MAX_ACCOUNT_IDENTITY_LENGTH);
        assert!(validate_config_request(&config_create(&at_limit, None)).is_ok());

        let over_limit = "a".repeat(MAX_ACCOUNT_IDENTITY_LENGTH + 1);
        assert_eq!(
            validate_config_request(&config_create(&over_limit, None)),
            Err(RotationValidationError::InvalidAccountIdentity)
        );
    }
}
