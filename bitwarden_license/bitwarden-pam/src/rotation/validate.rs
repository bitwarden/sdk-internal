use thiserror::Error;

use super::{
    configs::{RotationConfigCreateRequest, RotationConfigUpdateRequest},
    models::PasswordPolicy,
    schedule::is_likely_quartz_cron,
    target_systems::{TargetSystemCreateRequest, TargetSystemUpdateRequest},
};

/// Maximum length of a connector or target-system `name`, matching the server's column.
const MAX_NAME_LENGTH: usize = 200;
/// Maximum length of a config's `account_identity`, matching the server's column.
const MAX_ACCOUNT_IDENTITY_LENGTH: usize = 500;
/// Shortest generated credential a policy may ask for.
const MIN_PASSWORD_LENGTH: i32 = 1;
/// Longest generated credential a policy may ask for.
const MAX_PASSWORD_LENGTH: i32 = 999;

/// Errors returned when a locally-constructed rotation request fails validation before being sent.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RotationValidationError {
    /// A `name` was empty (after trimming) or exceeded the server's length limit.
    #[error("Name must be between 1 and {MAX_NAME_LENGTH} characters")]
    InvalidName,
    /// `account_identity` was empty (after trimming) or exceeded the server's length limit.
    #[error("Account identity must be between 1 and {MAX_ACCOUNT_IDENTITY_LENGTH} characters")]
    InvalidAccountIdentity,
    /// A password policy's length bounds were outside the permitted range, or `min_length`
    /// exceeded `max_length`.
    #[error(
        "Password length bounds must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}, with the minimum no greater than the maximum"
    )]
    InvalidPasswordLengthBounds,
    /// A password policy enabled no character classes, so no credential could satisfy it.
    #[error("A password policy must allow at least one character class")]
    NoCharacterClasses,
    /// `schedule_cron` was present but is not shaped like a Quartz cron expression.
    #[error("Schedule must be a 6- or 7-field Quartz cron expression")]
    InvalidCron,
}

/// Validates a name against the server's length limit.
///
/// Counted in UTF-16 code units to match the server's `nvarchar` column, so a name of astral
/// characters is measured the way the database will measure it rather than by Rust `char` count.
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

/// Validates a password policy.
///
/// Both checks mirror failures the connector's own generator raises at rotation time. Catching them
/// here means an operator learns while editing the target system, rather than from a rotation that
/// fails hours later against a policy no credential can satisfy.
fn validate_password_policy(policy: &PasswordPolicy) -> Result<(), RotationValidationError> {
    if policy.min_length < MIN_PASSWORD_LENGTH
        || policy.max_length > MAX_PASSWORD_LENGTH
        || policy.min_length > policy.max_length
    {
        return Err(RotationValidationError::InvalidPasswordLengthBounds);
    }

    if !policy.include_uppercase
        && !policy.include_lowercase
        && !policy.include_digits
        && !policy.include_symbols
    {
        return Err(RotationValidationError::NoCharacterClasses);
    }

    Ok(())
}

/// Validates a cron expression when one is set. `None` means no scheduled rotation, which is valid.
///
/// Only the shape is checked. The server owns the minimum-interval floor, because only it knows the
/// current limit - duplicating the number here would let the two disagree.
fn validate_schedule_cron(cron: Option<&String>) -> Result<(), RotationValidationError> {
    match cron {
        Some(cron) if !is_likely_quartz_cron(cron) => Err(RotationValidationError::InvalidCron),
        _ => Ok(()),
    }
}

/// Validates a target-system create request.
pub(super) fn validate_target_system_create(
    request: &TargetSystemCreateRequest,
) -> Result<(), RotationValidationError> {
    validate_name(request.name())?;
    validate_password_policy(request.password_policy())
}

/// Validates a target-system update request.
pub(super) fn validate_target_system_update(
    request: &TargetSystemUpdateRequest,
) -> Result<(), RotationValidationError> {
    validate_name(&request.name)?;
    validate_password_policy(&request.password_policy)
}

/// Validates a rotation-config create request.
pub(super) fn validate_config_create(
    request: &RotationConfigCreateRequest,
) -> Result<(), RotationValidationError> {
    validate_account_identity(&request.account_identity)?;
    validate_schedule_cron(request.schedule_cron.as_ref())
}

/// Validates a rotation-config update request.
pub(super) fn validate_config_update(
    request: &RotationConfigUpdateRequest,
) -> Result<(), RotationValidationError> {
    validate_account_identity(&request.account_identity)?;
    validate_schedule_cron(request.schedule_cron.as_ref())
}

#[cfg(test)]
mod tests {
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
        assert!(validate_target_system_create(&create_request("Prod SQL")).is_ok());
    }

    #[test]
    fn a_blank_name_is_rejected() {
        for name in ["", "   ", "\t\n"] {
            assert_eq!(
                validate_target_system_create(&create_request(name)),
                Err(RotationValidationError::InvalidName),
                "for {name:?}"
            );
        }
    }

    #[test]
    fn a_name_at_the_limit_passes_and_one_over_is_rejected() {
        let at_limit = "a".repeat(MAX_NAME_LENGTH);
        assert!(validate_target_system_create(&create_request(&at_limit)).is_ok());

        let over_limit = "a".repeat(MAX_NAME_LENGTH + 1);
        assert_eq!(
            validate_target_system_create(&create_request(&over_limit)),
            Err(RotationValidationError::InvalidName)
        );
    }

    /// The limit is the server's `nvarchar` budget, which counts UTF-16 code units. An astral
    /// character costs two, so 100 of them exactly fill a 200-unit column and 101 overflow it -
    /// a `char`-based count would wave both through.
    #[test]
    fn name_length_is_counted_in_utf16_code_units() {
        let at_limit = "😀".repeat(MAX_NAME_LENGTH / 2);
        assert!(validate_target_system_create(&create_request(&at_limit)).is_ok());

        let over_limit = "😀".repeat(MAX_NAME_LENGTH / 2 + 1);
        assert_eq!(
            validate_target_system_create(&create_request(&over_limit)),
            Err(RotationValidationError::InvalidName)
        );
    }

    /// Leading and trailing whitespace is trimmed before measuring, so padding cannot push an
    /// otherwise-valid name over.
    #[test]
    fn surrounding_whitespace_does_not_count_towards_the_limit() {
        let padded = format!("  {}  ", "a".repeat(MAX_NAME_LENGTH));
        assert!(validate_target_system_create(&create_request(&padded)).is_ok());
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
            validate_target_system_create(&request),
            Err(RotationValidationError::InvalidPasswordLengthBounds)
        );
    }

    #[test]
    fn length_bounds_outside_the_permitted_range_are_rejected() {
        for (min_length, max_length) in [(0, 64), (-1, 64), (14, MAX_PASSWORD_LENGTH + 1)] {
            let request = TargetSystemCreateRequest::Manual {
                name: "Manual".to_string(),
                password_policy: PasswordPolicy {
                    min_length,
                    max_length,
                    ..policy()
                },
            };

            assert_eq!(
                validate_target_system_create(&request),
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

        assert!(validate_target_system_create(&request).is_ok());
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
            validate_target_system_create(&request),
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

        assert!(validate_target_system_create(&request).is_ok());
    }

    #[test]
    fn a_config_with_no_schedule_is_valid() {
        assert!(validate_config_create(&config_create("svc_rotation", None)).is_ok());
    }

    #[test]
    fn a_config_with_a_well_formed_cron_is_valid() {
        assert!(
            validate_config_create(&config_create("svc_rotation", Some("0 0 0 * * ?"))).is_ok()
        );
    }

    #[test]
    fn a_malformed_cron_is_rejected() {
        // A 5-field UNIX cron - the likeliest operator mistake.
        assert_eq!(
            validate_config_create(&config_create("svc_rotation", Some("0 0 * * *"))),
            Err(RotationValidationError::InvalidCron)
        );
    }

    #[test]
    fn a_blank_account_identity_is_rejected() {
        assert_eq!(
            validate_config_create(&config_create("   ", None)),
            Err(RotationValidationError::InvalidAccountIdentity)
        );
    }

    #[test]
    fn an_account_identity_at_the_limit_passes_and_one_over_is_rejected() {
        let at_limit = "a".repeat(MAX_ACCOUNT_IDENTITY_LENGTH);
        assert!(validate_config_create(&config_create(&at_limit, None)).is_ok());

        let over_limit = "a".repeat(MAX_ACCOUNT_IDENTITY_LENGTH + 1);
        assert_eq!(
            validate_config_create(&config_create(&over_limit, None)),
            Err(RotationValidationError::InvalidAccountIdentity)
        );
    }

    /// The update path guards the same fields as create; a caller must not be able to reach an
    /// invalid state by editing into it.
    #[test]
    fn the_update_path_applies_the_same_guards() {
        let request = RotationConfigUpdateRequest {
            account_identity: String::new(),
            terminate_sessions: false,
            schedule_cron: None,
            rotate_on_access_end: false,
        };
        assert_eq!(
            validate_config_update(&request),
            Err(RotationValidationError::InvalidAccountIdentity)
        );

        let request = TargetSystemUpdateRequest {
            name: "Renamed".to_string(),
            password_policy: PasswordPolicy {
                min_length: 64,
                max_length: 14,
                ..policy()
            },
            supports_session_termination: false,
        };
        assert_eq!(
            validate_target_system_update(&request),
            Err(RotationValidationError::InvalidPasswordLengthBounds)
        );
    }
}
