use bitwarden_pam_sealed::{PasswordPolicyError, SealedPasswordPolicy};
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
    /// Password lengths out of order or outside the generator's range.
    #[error("Password length bounds are outside the generator's supported range")]
    InvalidPasswordLengthBounds,
    /// A password policy enabled no character classes, so no credential could satisfy it.
    #[error("A password policy must allow at least one character class")]
    NoCharacterClasses,
    /// `schedule_cron` was present but is not shaped like a Quartz cron expression.
    #[error("Schedule must be a 6- or 7-field Quartz cron expression")]
    InvalidCron,
    /// `terminate_sessions` was requested but the target doesn't confirm
    /// `supports_session_termination`.
    #[error("The target system does not confirm it supports session termination")]
    SessionTerminationUnsupported,
    /// The rotation config's target system has a sealed blob that can't be verified.
    #[error("The target system's sealed data is invalid")]
    TargetSystemSealInvalid,
    /// An update tried to change a target system's `method`.
    #[error("Target system method cannot be changed")]
    TargetSystemMethodMismatch,
    /// An update tried to change a target system's sealed `kind`.
    #[error("Target system kind cannot be changed")]
    TargetSystemKindMismatch,
    /// An update tried to change a rotation config's `cipher_id` or `target_system_id`.
    #[error("Rotation config cipher or target system cannot be changed")]
    RotationConfigImmutableFieldMismatch,
}

impl From<PasswordPolicyError> for RotationValidationError {
    fn from(error: PasswordPolicyError) -> Self {
        match error {
            PasswordPolicyError::NoCharacterClasses => Self::NoCharacterClasses,
            PasswordPolicyError::InvalidLengthBounds => Self::InvalidPasswordLengthBounds,
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

/// The access connector applies the same check, so an unsatisfiable policy is caught while editing
/// rather than at rotation.
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

/// Validates a target system request.
pub(super) fn validate_target_system_request(
    request: &TargetSystemCreateRequest,
) -> Result<(), RotationValidationError> {
    validate_name(request.name())?;
    validate_password_policy(request.password_policy())
}

/// Validates a rotation config request. `terminate_sessions` is checked against the target
/// separately, since that needs a network call.
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
