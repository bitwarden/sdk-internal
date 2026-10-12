//! Shared password-strength floor for PAM-generated credentials.
//!
//! The sealed blobs stop a hostile server from *changing* a target's password policy in transit,
//! but not from replaying an old, weak policy, or one sealed by a colluding org member. Both the
//! admin client (when saving a policy) and the access connector (when honoring a claim) must
//! therefore refuse any policy whose generated password falls below a fixed entropy floor. Living
//! here means both call sites enforce exactly the same rule.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Minimum number of bits of entropy a [`SealedPasswordPolicy`] must produce to pass
/// [`SealedPasswordPolicy::validate`].
pub const MIN_PASSWORD_ENTROPY_BITS: f64 = 80.0;

/// Shortest password length the generator (`bitwarden_generators::MINIMUM_PASSWORD_LENGTH`) will
/// produce. Duplicated here (rather than depending on `bitwarden-generators` directly) because
/// this crate must stay dependency-light for the access connector; a unit test asserts the two
/// stay equal.
pub const GENERATOR_MIN_LENGTH: u32 = 5;
/// Longest password length the generator (`bitwarden_generators::MAXIMUM_PASSWORD_LENGTH`) will
/// produce. See [`GENERATOR_MIN_LENGTH`] for why this is duplicated rather than imported.
pub const GENERATOR_MAX_LENGTH: u32 = 128;

/// Size of the generator's lowercase character set (`a`-`z`) with `avoid_ambiguous: false`.
const LOWERCASE_SET_SIZE: u32 = 26;
/// Size of the generator's uppercase character set (`A`-`Z`) with `avoid_ambiguous: false`.
const UPPERCASE_SET_SIZE: u32 = 26;
/// Size of the generator's digit character set (`0`-`9`) with `avoid_ambiguous: false`.
const DIGIT_SET_SIZE: u32 = 10;
/// Size of the generator's symbol character set (`! @ # $ % ^ & *`).
const SYMBOL_SET_SIZE: u32 = 8;

/// Errors returned by [`SealedPasswordPolicy::validate`].
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PolicyStrengthError {
    /// No character class (uppercase, lowercase, digits or symbols) is enabled, so no password
    /// could be generated.
    #[error("No character classes are enabled")]
    NoCharacterClasses,
    /// `min_length` and `max_length` are out of order, or fall outside the generator's supported
    /// range (`[GENERATOR_MIN_LENGTH, GENERATOR_MAX_LENGTH]`).
    #[error("Invalid length bounds")]
    InvalidLengthBounds,
    /// The policy's generated password would have less than [`MIN_PASSWORD_ENTROPY_BITS`] of
    /// entropy.
    #[error("Policy falls below the minimum password strength floor")]
    BelowStrengthFloor,
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
    /// The size of the character pool the generator draws from, given which classes are enabled.
    fn character_pool_size(&self) -> u32 {
        let mut pool = 0;
        if self.include_uppercase {
            pool += UPPERCASE_SET_SIZE;
        }
        if self.include_lowercase {
            pool += LOWERCASE_SET_SIZE;
        }
        if self.include_digits {
            pool += DIGIT_SET_SIZE;
        }
        if self.include_symbols {
            pool += SYMBOL_SET_SIZE;
        }
        pool
    }

    /// The entropy, in bits, of a password generated under this policy: `length × log2(pool)`,
    /// where `length` is `max_length` clamped to the generator's supported range and `pool` is the
    /// size of the enabled character pool (0 if no class is enabled, giving 0 bits of entropy).
    pub fn entropy_bits(&self) -> f64 {
        let pool = self.character_pool_size();
        if pool == 0 {
            return 0.0;
        }
        let length = self
            .max_length
            .clamp(GENERATOR_MIN_LENGTH, GENERATOR_MAX_LENGTH);
        f64::from(length) * f64::from(pool).log2()
    }

    /// Validates this policy against the shared strength floor: at least one character class is
    /// enabled, the length bounds are sane and within the generator's supported range, and the
    /// resulting entropy meets [`MIN_PASSWORD_ENTROPY_BITS`].
    pub fn validate(&self) -> Result<(), PolicyStrengthError> {
        if self.character_pool_size() == 0 {
            return Err(PolicyStrengthError::NoCharacterClasses);
        }
        if !(GENERATOR_MIN_LENGTH <= self.min_length
            && self.min_length <= self.max_length
            && self.max_length <= GENERATOR_MAX_LENGTH)
        {
            return Err(PolicyStrengthError::InvalidLengthBounds);
        }
        if self.entropy_bits() < MIN_PASSWORD_ENTROPY_BITS {
            return Err(PolicyStrengthError::BelowStrengthFloor);
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

    /// Exercises the real generator with a single character class enabled at a time, at the
    /// maximum password length, across many independently-seeded passwords, and checks the union
    /// of observed characters has exactly the size hard-coded in this module. With length 128 and
    /// 40 passwords (5120 draws from a <=26-symbol pool), the chance any reachable character is
    /// never drawn is astronomically small (coupon-collector tail), so this reliably catches drift
    /// between the generator's actual character sets and the consts above.
    #[test]
    fn generator_char_set_sizes_match_hardcoded_consts() {
        use std::collections::BTreeSet;

        use bitwarden_core::Client;
        use bitwarden_generators::{GeneratorClientsExt, PasswordGeneratorRequest};

        fn observed_chars(request: impl Fn() -> PasswordGeneratorRequest) -> BTreeSet<char> {
            let client = Client::new(None);
            let generator = client.generator();
            let mut seen = BTreeSet::new();
            for _ in 0..40 {
                let password = generator.password(request()).expect("valid request");
                seen.extend(password.chars());
            }
            seen
        }

        let base = || PasswordGeneratorRequest {
            lowercase: false,
            uppercase: false,
            numbers: false,
            special: false,
            length: u8::try_from(GENERATOR_MAX_LENGTH).expect("fits in u8"),
            avoid_ambiguous: false,
            min_lowercase: None,
            min_uppercase: None,
            min_number: None,
            min_special: None,
            custom_required_chars: None,
            custom_allowed_chars: None,
            max_consecutive: None,
        };

        let lowercase = observed_chars(|| PasswordGeneratorRequest {
            lowercase: true,
            ..base()
        });
        assert_eq!(lowercase.len() as u32, LOWERCASE_SET_SIZE);

        let uppercase = observed_chars(|| PasswordGeneratorRequest {
            uppercase: true,
            ..base()
        });
        assert_eq!(uppercase.len() as u32, UPPERCASE_SET_SIZE);

        let digits = observed_chars(|| PasswordGeneratorRequest {
            numbers: true,
            ..base()
        });
        assert_eq!(digits.len() as u32, DIGIT_SET_SIZE);

        let symbols = observed_chars(|| PasswordGeneratorRequest {
            special: true,
            ..base()
        });
        assert_eq!(symbols.len() as u32, SYMBOL_SET_SIZE);
    }

    #[test]
    fn entropy_all_classes_length_14_meets_floor() {
        // 14 * log2(26+26+10+8) = 14 * log2(70) ~= 14 * 6.129 ~= 85.8 bits.
        let policy = all_classes(14);
        let entropy = policy.entropy_bits();
        assert!(
            entropy >= MIN_PASSWORD_ENTROPY_BITS,
            "entropy was {entropy}"
        );
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn entropy_digits_only_length_20_is_below_floor() {
        // 20 * log2(10) ~= 20 * 3.32 ~= 66.4 bits < 80.
        let policy = SealedPasswordPolicy {
            min_length: GENERATOR_MIN_LENGTH,
            max_length: 20,
            include_uppercase: false,
            include_lowercase: false,
            include_digits: true,
            include_symbols: false,
        };
        let entropy = policy.entropy_bits();
        assert!(entropy < MIN_PASSWORD_ENTROPY_BITS, "entropy was {entropy}");
        assert_eq!(
            policy.validate(),
            Err(PolicyStrengthError::BelowStrengthFloor)
        );
    }

    #[test]
    fn entropy_clamps_max_length_to_generator_range() {
        // A max_length above the generator's ceiling is clamped down before computing entropy.
        let huge = all_classes(GENERATOR_MAX_LENGTH + 1000);
        let clamped = all_classes(GENERATOR_MAX_LENGTH);
        assert_eq!(huge.entropy_bits(), clamped.entropy_bits());
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
            Err(PolicyStrengthError::NoCharacterClasses)
        );
    }

    #[test]
    fn validate_rejects_min_length_above_max_length() {
        let mut policy = all_classes(14);
        policy.min_length = 15;
        assert_eq!(
            policy.validate(),
            Err(PolicyStrengthError::InvalidLengthBounds)
        );
    }

    #[test]
    fn validate_rejects_max_length_above_generator_range() {
        let mut policy = all_classes(GENERATOR_MAX_LENGTH);
        policy.max_length = GENERATOR_MAX_LENGTH + 1;
        assert_eq!(
            policy.validate(),
            Err(PolicyStrengthError::InvalidLengthBounds)
        );
    }

    #[test]
    fn validate_rejects_min_length_below_generator_range() {
        let mut policy = all_classes(14);
        policy.min_length = GENERATOR_MIN_LENGTH - 1;
        assert_eq!(
            policy.validate(),
            Err(PolicyStrengthError::InvalidLengthBounds)
        );
    }
}
