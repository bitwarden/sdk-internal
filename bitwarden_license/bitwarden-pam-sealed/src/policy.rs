//! Shared generator-validity check for sealed password policies.
//!
//! [`SealedPasswordPolicy::validate`] only checks that the generator can produce a password for
//! the policy; password strength is the customer's call.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Shortest password length the generator (`bitwarden_generators::MINIMUM_PASSWORD_LENGTH`) will
/// produce. Duplicated here, rather than depending on `bitwarden-generators` directly, to keep
/// this crate dependency-light for the access connector; a unit test asserts the two stay equal.
pub const GENERATOR_MIN_LENGTH: u32 = 5;
/// Longest password length the generator (`bitwarden_generators::MAXIMUM_PASSWORD_LENGTH`) will
/// produce. See [`GENERATOR_MIN_LENGTH`] for why this is duplicated rather than imported.
pub const GENERATOR_MAX_LENGTH: u32 = 128;

/// Errors returned by [`SealedPasswordPolicy::validate`].
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PasswordPolicyError {
    /// No character class is enabled, so no password could be generated.
    #[error("No character classes are enabled")]
    NoCharacterClasses,
    /// `min_length` and `max_length` are out of order, or fall outside the generator's supported
    /// range (`[GENERATOR_MIN_LENGTH, GENERATOR_MAX_LENGTH]`).
    #[error("Invalid length bounds")]
    InvalidLengthBounds,
}

/// A password policy for a PAM target system's automatically-generated credential.
///
/// `max_length` is the length the connector actually generates: it is clamped to the generator's
/// supported range (`[GENERATOR_MIN_LENGTH, GENERATOR_MAX_LENGTH]`) before use. `min_length` only
/// bounds the policy itself (see [`Self::validate`]); it does not change what gets generated.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SealedPasswordPolicy {
    /// Lower bound on `max_length`, checked by [`Self::validate`]. Does not affect generation.
    pub min_length: u32,
    /// The length of password the connector generates, clamped to
    /// `[GENERATOR_MIN_LENGTH, GENERATOR_MAX_LENGTH]`.
    pub max_length: u32,
    /// Whether the generated password includes uppercase letters (`A`-`Z`).
    pub include_uppercase: bool,
    /// Whether the generated password includes lowercase letters (`a`-`z`).
    pub include_lowercase: bool,
    /// Whether the generated password includes digits (`0`-`9`).
    pub include_digits: bool,
    /// Whether the generated password includes symbols (`! @ # $ % ^ & *`).
    pub include_symbols: bool,
}

impl SealedPasswordPolicy {
    /// Whether at least one character class is enabled.
    fn has_character_class(&self) -> bool {
        self.include_uppercase
            || self.include_lowercase
            || self.include_digits
            || self.include_symbols
    }

    /// Validates that the generator can produce a password for this policy: at least one
    /// character class enabled, and length bounds within the generator's supported range.
    pub fn validate(&self) -> Result<(), PasswordPolicyError> {
        if !self.has_character_class() {
            return Err(PasswordPolicyError::NoCharacterClasses);
        }
        if !(GENERATOR_MIN_LENGTH <= self.min_length
            && self.min_length <= self.max_length
            && self.max_length <= GENERATOR_MAX_LENGTH)
        {
            return Err(PasswordPolicyError::InvalidLengthBounds);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_classes(max_length: u32) -> SealedPasswordPolicy {
        SealedPasswordPolicy {
            min_length: GENERATOR_MIN_LENGTH,
            max_length,
            include_uppercase: true,
            include_lowercase: true,
            include_digits: true,
            include_symbols: true,
        }
    }

    #[test]
    fn generator_consts_match_bitwarden_generators() {
        assert_eq!(
            GENERATOR_MIN_LENGTH,
            u32::from(bitwarden_generators::MINIMUM_PASSWORD_LENGTH)
        );
        assert_eq!(
            GENERATOR_MAX_LENGTH,
            u32::from(bitwarden_generators::MAXIMUM_PASSWORD_LENGTH)
        );
    }

    #[test]
    fn validate_rejects_no_character_classes() {
        let policy = SealedPasswordPolicy {
            min_length: GENERATOR_MIN_LENGTH,
            max_length: 20,
            include_uppercase: false,
            include_lowercase: false,
            include_digits: false,
            include_symbols: false,
        };
        assert_eq!(
            policy.validate(),
            Err(PasswordPolicyError::NoCharacterClasses)
        );
    }

    #[test]
    fn validate_rejects_min_length_above_max_length() {
        let mut policy = all_classes(14);
        policy.min_length = 15;
        assert_eq!(
            policy.validate(),
            Err(PasswordPolicyError::InvalidLengthBounds)
        );
    }

    #[test]
    fn validate_rejects_max_length_above_generator_range() {
        let mut policy = all_classes(GENERATOR_MAX_LENGTH);
        policy.max_length = GENERATOR_MAX_LENGTH + 1;
        assert_eq!(
            policy.validate(),
            Err(PasswordPolicyError::InvalidLengthBounds)
        );
    }

    #[test]
    fn validate_rejects_min_length_below_generator_range() {
        let mut policy = all_classes(14);
        policy.min_length = GENERATOR_MIN_LENGTH - 1;
        assert_eq!(
            policy.validate(),
            Err(PasswordPolicyError::InvalidLengthBounds)
        );
    }

    /// A weak but generator-valid policy (digits only, shortest allowed length) passes: password
    /// strength is the customer's call, not this crate's.
    #[test]
    fn weak_but_generator_valid_policy_passes() {
        let policy = SealedPasswordPolicy {
            min_length: GENERATOR_MIN_LENGTH,
            max_length: GENERATOR_MIN_LENGTH,
            include_uppercase: false,
            include_lowercase: false,
            include_digits: true,
            include_symbols: false,
        };
        assert!(policy.validate().is_ok());
    }
}
