//! Rotation policy models and evaluation logic.
//!
//! Converts the server-supplied [`PasswordPolicy`] snapshot from a claimed rotation job
//! into a [`PasswordGeneratorRequest`] that the generators crate can execute.

use bitwarden_generators::{
    MAXIMUM_PASSWORD_LENGTH, MINIMUM_PASSWORD_LENGTH, PasswordGeneratorRequest,
};
use serde::Deserialize;
use thiserror::Error;

/// Errors that can occur when converting a [`PasswordPolicy`] into a generator request.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum PolicyError {
    /// All character-class flags (`include_uppercase`, `include_lowercase`,
    /// `include_digits`, `include_symbols`) are `false`. At least one must be enabled.
    #[error("password policy requires at least one character class to be enabled")]
    NoCharacterClasses,
    /// `min_length` exceeds `max_length`, or the effective floor (after clamping to the
    /// generator minimum of {MINIMUM_PASSWORD_LENGTH}) exceeds the generator maximum of
    /// {MAXIMUM_PASSWORD_LENGTH}.
    #[error("password policy has invalid length bounds")]
    InvalidBounds,
}

/// Password-policy snapshot delivered inside a rotation claim.
///
/// Field names use the wire casing from the server's OpenAPI spec (camelCase or
/// snake_case depending on the generated bindings). We accept both via `#[serde(alias)]`
/// so that hand-written tests and future generated-model migration can coexist.
///
/// Note: `include_digits` maps to `numbers` in `PasswordGeneratorRequest` and
/// `include_symbols` maps to `special` — the generator crate uses its own naming.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PasswordPolicy {
    /// Minimum password length enforced by the policy.  `None` means unconstrained
    /// (the generator minimum of 5 is still applied).
    #[serde(alias = "min_length")]
    pub(crate) min_length: Option<u32>,

    /// Maximum password length enforced by the policy.  `None` means the default
    /// target length of 64 characters is used.
    #[serde(alias = "max_length")]
    pub(crate) max_length: Option<u32>,

    /// Whether uppercase letters (A–Z) must be included.
    #[serde(alias = "include_uppercase")]
    pub(crate) include_uppercase: bool,

    /// Whether lowercase letters (a–z) must be included.
    #[serde(alias = "include_lowercase")]
    pub(crate) include_lowercase: bool,

    /// Whether decimal digits (0–9) must be included.
    #[serde(alias = "include_digits")]
    pub(crate) include_digits: bool,

    /// Whether special/symbol characters must be included.
    #[serde(alias = "include_symbols")]
    pub(crate) include_symbols: bool,
}

/// The default password length used when the policy specifies no `max_length`.
const DEFAULT_POLICY_PASSWORD_LENGTH: u32 = 64;

/// Convert a [`PasswordPolicy`] into a [`PasswordGeneratorRequest`] ready for the
/// password generator.
///
/// # Errors
///
/// - [`PolicyError::NoCharacterClasses`] — all four `include_*` flags are `false`.
/// - [`PolicyError::InvalidBounds`] — `min_length > max_length` (when both are `Some`), or the
///   effective floor (after applying the generator minimum of 5) exceeds the generator maximum of
///   128.
pub(crate) fn to_generator_request(
    policy: &PasswordPolicy,
) -> Result<PasswordGeneratorRequest, PolicyError> {
    // At least one character class must be enabled.
    if !policy.include_uppercase
        && !policy.include_lowercase
        && !policy.include_digits
        && !policy.include_symbols
    {
        return Err(PolicyError::NoCharacterClasses);
    }

    // Validate explicit bounds before computing the target length.
    if let (Some(min), Some(max)) = (policy.min_length, policy.max_length)
        && min > max
    {
        return Err(PolicyError::InvalidBounds);
    }

    // Generator minimum: MINIMUM_PASSWORD_LENGTH = 5 (u8).
    let gen_min = u32::from(MINIMUM_PASSWORD_LENGTH);
    // Generator maximum: MAXIMUM_PASSWORD_LENGTH = 128 (u8).
    let gen_max = u32::from(MAXIMUM_PASSWORD_LENGTH);

    // Effective floor: max(policy min_length, generator minimum 5).
    let floor = policy.min_length.unwrap_or(0).max(gen_min);

    // The floor itself must not exceed the generator maximum.
    if floor > gen_max {
        return Err(PolicyError::InvalidBounds);
    }

    // Target length: clamp(max_length.unwrap_or(64), floor, 128).
    let raw_max = policy.max_length.unwrap_or(DEFAULT_POLICY_PASSWORD_LENGTH);
    let length_u32 = raw_max.clamp(floor, gen_max);

    // Safety: length_u32 is in [floor, 128] ⊆ [0, 128] which fits in u8.
    #[allow(clippy::cast_possible_truncation)]
    let length = length_u32 as u8;

    Ok(PasswordGeneratorRequest {
        lowercase: policy.include_lowercase,
        uppercase: policy.include_uppercase,
        numbers: policy.include_digits,
        special: policy.include_symbols,
        length,
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

#[cfg(test)]
mod tests {
    use bitwarden_generators::password;

    use super::*;

    /// Helper: build a maximally permissive policy and override individual fields.
    fn all_classes(min: Option<u32>, max: Option<u32>) -> PasswordPolicy {
        PasswordPolicy {
            min_length: min,
            max_length: max,
            include_uppercase: true,
            include_lowercase: true,
            include_digits: true,
            include_symbols: true,
        }
    }

    // ── Basic mapping ────────────────────────────────────────────────────────────────

    #[test]
    fn test_defaults_produce_length_64() {
        // No bounds → length = clamp(64, 5, 128) = 64.
        let req = to_generator_request(&all_classes(None, None)).unwrap();
        assert_eq!(req.length, 64);
    }

    #[test]
    fn test_explicit_max_within_range_is_honored() {
        let req = to_generator_request(&all_classes(None, Some(20))).unwrap();
        assert_eq!(req.length, 20);
    }

    #[test]
    fn test_min_and_max_both_set_honors_max() {
        let req = to_generator_request(&all_classes(Some(10), Some(50))).unwrap();
        assert_eq!(req.length, 50);
    }

    // ── Floor: generator minimum of 5 ───────────────────────────────────────────────

    #[test]
    fn test_min_length_zero_floors_to_generator_min() {
        // min_length=0 → floor = max(0, 5) = 5; max defaults to 64 → length = 64.
        let req = to_generator_request(&all_classes(Some(0), None)).unwrap();
        assert_eq!(req.length, 64);
    }

    #[test]
    fn test_min_length_below_generator_min_floors_to_5() {
        // min_length=3 → floor = max(3, 5) = 5; max = 10 → length = 10.
        let req = to_generator_request(&all_classes(Some(3), Some(10))).unwrap();
        assert_eq!(req.length, 10);
        // floor (5) <= length (10) is valid.
    }

    #[test]
    fn test_min_length_exactly_5_is_valid() {
        let req = to_generator_request(&all_classes(Some(5), Some(5))).unwrap();
        assert_eq!(req.length, 5);
    }

    // ── Clamp at generator maximum (128) ────────────────────────────────────────────

    #[test]
    fn test_max_length_above_128_clamps_to_128() {
        // max_length > 128 → clamp to 128.
        let req = to_generator_request(&all_classes(None, Some(200))).unwrap();
        assert_eq!(req.length, 128);
    }

    #[test]
    fn test_max_length_exactly_128_is_accepted() {
        let req = to_generator_request(&all_classes(None, Some(128))).unwrap();
        assert_eq!(req.length, 128);
    }

    // ── Error: min > max ────────────────────────────────────────────────────────────

    #[test]
    fn test_min_greater_than_max_returns_invalid_bounds() {
        let err = to_generator_request(&all_classes(Some(50), Some(30))).unwrap_err();
        assert_eq!(err, PolicyError::InvalidBounds);
    }

    #[test]
    fn test_min_equal_max_is_valid() {
        let req = to_generator_request(&all_classes(Some(16), Some(16))).unwrap();
        assert_eq!(req.length, 16);
    }

    // ── Error: floor > 128 ──────────────────────────────────────────────────────────

    #[test]
    fn test_min_length_above_128_returns_invalid_bounds() {
        // floor = max(200, 5) = 200 > 128 → InvalidBounds.
        let err = to_generator_request(&all_classes(Some(200), None)).unwrap_err();
        assert_eq!(err, PolicyError::InvalidBounds);
    }

    #[test]
    fn test_min_length_exactly_128_is_valid() {
        // floor = 128 == gen_max → clamp(max(128), 128, 128) = 128.
        let req = to_generator_request(&all_classes(Some(128), Some(128))).unwrap();
        assert_eq!(req.length, 128);
    }

    // ── Error: no character classes ─────────────────────────────────────────────────

    #[test]
    fn test_all_classes_false_returns_no_character_classes() {
        let policy = PasswordPolicy {
            min_length: None,
            max_length: None,
            include_uppercase: false,
            include_lowercase: false,
            include_digits: false,
            include_symbols: false,
        };
        let err = to_generator_request(&policy).unwrap_err();
        assert_eq!(err, PolicyError::NoCharacterClasses);
    }

    #[test]
    fn test_single_class_enabled_is_sufficient() {
        for (upper, lower, digits, symbols) in [
            (true, false, false, false),
            (false, true, false, false),
            (false, false, true, false),
            (false, false, false, true),
        ] {
            let policy = PasswordPolicy {
                min_length: None,
                max_length: None,
                include_uppercase: upper,
                include_lowercase: lower,
                include_digits: digits,
                include_symbols: symbols,
            };
            assert!(
                to_generator_request(&policy).is_ok(),
                "expected Ok when only one class is enabled: \
                 upper={upper} lower={lower} digits={digits} symbols={symbols}"
            );
        }
    }

    // ── Character-class mapping ──────────────────────────────────────────────────────

    #[test]
    fn test_include_flags_map_correctly() {
        let policy = PasswordPolicy {
            min_length: None,
            max_length: None,
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
        // Minimums and custom fields left as None.
        assert!(req.min_uppercase.is_none());
        assert!(req.min_lowercase.is_none());
        assert!(req.min_number.is_none());
        assert!(req.min_special.is_none());
        assert!(!req.avoid_ambiguous);
        assert!(req.custom_required_chars.is_none());
        assert!(req.custom_allowed_chars.is_none());
        assert!(req.max_consecutive.is_none());
    }

    // ── End-to-end: generated request passes validate_options and produces a password ─

    #[test]
    fn test_generated_request_produces_valid_password() {
        // Verify that to_generator_request output passes through the generator without error.
        let req = to_generator_request(&all_classes(Some(12), Some(32))).unwrap();
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
    fn test_generated_password_uses_only_enabled_charset() {
        // Only digits: all characters in output must be ASCII digit.
        let policy = PasswordPolicy {
            min_length: Some(10),
            max_length: Some(10),
            include_uppercase: false,
            include_lowercase: false,
            include_digits: true,
            include_symbols: false,
        };
        let req = to_generator_request(&policy).unwrap();
        assert_eq!(req.length, 10);
        let pwd = password(req).unwrap();
        assert!(
            pwd.chars().all(|c| c.is_ascii_digit()),
            "expected only digits in {pwd:?}"
        );
    }

    #[test]
    fn test_generated_password_at_maximum_length() {
        // max = 128 → length = 128 → generator should succeed.
        let req = to_generator_request(&all_classes(None, Some(128))).unwrap();
        assert_eq!(req.length, 128);
        let pwd = password(req).unwrap();
        assert_eq!(pwd.len(), 128);
    }
}
