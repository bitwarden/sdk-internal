//! Translation layer that adapts [`password_rules_parser`] output to the SDK's
//! [`PasswordGeneratorRequest`] shape.
//!
//! Reference: Apple's [password-manager-resources spec][apple-spec] (also a WHATWG proposal).
//! The parsing itself is delegated to the third-party `password-rules-parser` crate
//! (maintained by 1Password). This module handles SDK-specific concerns:
//!
//!   - clamping length into [`MINIMUM_PASSWORD_LENGTH`, `MAXIMUM_PASSWORD_LENGTH`];
//!   - applying the spec's defaults for `allowed` when `required` is present;
//!   - flattening the parser's `Vec<Vec<CharacterClass>>` required model into the SDK's flat
//!     AND-of-classes model with `min_*` counts;
//!   - shaping errors for WASM/UniFFI via [`bitwarden_error(flat)`].
//!
//! [apple-spec]: https://github.com/apple/password-manager-resources

use std::collections::BTreeSet;

use bitwarden_error::bitwarden_error;
use password_rules_parser::{
    CharacterClass, PasswordRules, parse_password_rules as parse_external,
};
use thiserror::Error;

use crate::password::{MAXIMUM_PASSWORD_LENGTH, MINIMUM_PASSWORD_LENGTH, PasswordGeneratorRequest};

/// Errors that may occur while parsing an HTML `passwordrules` attribute.
#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PasswordRulesError {
    /// The input was syntactically invalid (unknown property, malformed rule, bad
    /// custom class, etc.). The wrapped string is a human-readable description of the
    /// failure from the underlying parser.
    #[error("Failed to parse password rules: {0}")]
    Parse(String),
    /// `minlength` exceeds `maxlength`, or `max_consecutive` does not fit in a `u8`.
    #[error("Invalid length constraint")]
    InvalidLength,
}

/// Default password length used when no `minlength`/`maxlength` constrains the choice.
const DEFAULT_LENGTH: u32 = 16;

/// Maximum length (in characters) of any user-supplied substring echoed back in errors.
/// Keeps error payloads bounded as they cross the WASM/UniFFI boundary.
const MAX_ECHOED_VALUE_LEN: usize = 64;

/// Trims `s` and, if it exceeds [`MAX_ECHOED_VALUE_LEN`] characters, truncates to that many
/// characters followed by an ellipsis. Operates on `char` boundaries, so it is UTF-8 safe.
fn truncate_for_error(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.chars().count() <= MAX_ECHOED_VALUE_LEN {
        trimmed.to_string()
    } else {
        let truncated: String = trimmed.chars().take(MAX_ECHOED_VALUE_LEN).collect();
        format!("{truncated}…")
    }
}

/// The standard character classes from a single `required` or `allowed` rule, flattened
/// into the SDK's "this class is enabled" boolean model. The parser exposes `required`
/// as `Vec<Vec<CharacterClass>>` (AND of ORs), but the SDK's [`PasswordGeneratorRequest`]
/// only models a flat AND of classes — so any nested OR groups are flattened by taking
/// the union of their classes.
#[derive(Default, Debug, Clone)]
struct AccumulatedClasses {
    upper: bool,
    lower: bool,
    digit: bool,
    special: bool,
    custom: BTreeSet<char>,
}

impl AccumulatedClasses {
    fn is_empty(&self) -> bool {
        !self.upper && !self.lower && !self.digit && !self.special && self.custom.is_empty()
    }

    fn apply(&mut self, class: &CharacterClass) {
        match class {
            CharacterClass::Upper => self.upper = true,
            CharacterClass::Lower => self.lower = true,
            CharacterClass::Digit => self.digit = true,
            CharacterClass::Special => self.special = true,
            // `ascii-printable` and `unicode` keywords are treated as enabling all four
            // standard classes. The SDK doesn't generate beyond ASCII-printable, so the
            // two are equivalent for our purposes.
            CharacterClass::AsciiPrintable | CharacterClass::Unicode => {
                self.upper = true;
                self.lower = true;
                self.digit = true;
                self.special = true;
            }
            CharacterClass::Custom(chars) => {
                // Restrict to ASCII-graphic characters so the generated pool stays inside
                // the SDK's expected character range.
                self.custom
                    .extend(chars.iter().copied().filter(|c| c.is_ascii_graphic()));
            }
        }
    }
}

/// Parses an HTML `passwordrules` attribute string into a [`PasswordGeneratorRequest`].
///
/// Empty or whitespace-only input is accepted and resolves to the spec default
/// (`allowed: ascii-printable`).
pub fn parse_password_rules(rules: &str) -> Result<PasswordGeneratorRequest, PasswordRulesError> {
    // Short-circuit empty/whitespace input rather than relying on the external parser's
    // behavior for it; matches the spec default and keeps the empty-input path simple.
    if rules.trim().is_empty() {
        return assemble_request(
            None,
            None,
            None,
            AccumulatedClasses::default(),
            AccumulatedClasses::default(),
            false,
        );
    }

    let parsed = parse_external(rules, false).map_err(parse_error_to_sdk)?;

    let PasswordRules {
        min_length,
        max_length,
        max_consecutive,
        allowed,
        required,
    } = parsed;

    let mut required_classes = AccumulatedClasses::default();
    for group in &required {
        for cls in group {
            required_classes.apply(cls);
        }
    }

    let mut allowed_classes = AccumulatedClasses::default();
    let allowed_seen = !allowed.is_empty();
    for cls in &allowed {
        allowed_classes.apply(cls);
    }

    assemble_request(
        min_length,
        max_length,
        max_consecutive,
        required_classes,
        allowed_classes,
        allowed_seen,
    )
}

/// Build the final [`PasswordGeneratorRequest`] from the accumulated rule state.
fn assemble_request(
    min_length: Option<u32>,
    max_length: Option<u32>,
    max_consecutive: Option<u32>,
    required: AccumulatedClasses,
    mut allowed: AccumulatedClasses,
    allowed_seen: bool,
) -> Result<PasswordGeneratorRequest, PasswordRulesError> {
    // Spec defaults:
    //  - If `required` is given but `allowed` is not, `allowed` defaults to the required set.
    //  - If neither is given, `allowed` defaults to `ascii-printable` (all four standard classes).
    if !allowed_seen {
        if !required.is_empty() {
            allowed = required.clone();
        } else {
            allowed.upper = true;
            allowed.lower = true;
            allowed.digit = true;
            allowed.special = true;
        }
    }

    let length = resolve_length(min_length, max_length)?;

    let lowercase = allowed.lower || required.lower;
    let uppercase = allowed.upper || required.upper;
    let numbers = allowed.digit || required.digit;
    let special = allowed.special || required.special;

    let custom_required_chars: Option<String> = if required.custom.is_empty() {
        None
    } else {
        Some(required.custom.iter().collect())
    };
    let custom_allowed_union: BTreeSet<char> = allowed
        .custom
        .iter()
        .chain(required.custom.iter())
        .copied()
        .collect();
    let custom_allowed_chars: Option<String> = if custom_allowed_union.is_empty() {
        None
    } else {
        Some(custom_allowed_union.into_iter().collect())
    };

    let max_consecutive = match max_consecutive {
        Some(v) => Some(u8::try_from(v).map_err(|_| PasswordRulesError::InvalidLength)?),
        None => None,
    };

    Ok(PasswordGeneratorRequest {
        lowercase,
        uppercase,
        numbers,
        special,
        length,
        avoid_ambiguous: false,
        min_lowercase: required.lower.then_some(1),
        min_uppercase: required.upper.then_some(1),
        min_number: required.digit.then_some(1),
        min_special: required.special.then_some(1),
        custom_required_chars,
        custom_allowed_chars,
        max_consecutive,
    })
}

/// Resolves the final password length from the (un-clamped) `min_length`/`max_length`
/// parsed from the input, applying the SDK's `[MINIMUM_PASSWORD_LENGTH, MAXIMUM_PASSWORD_LENGTH]`
/// clamp and validating that `min_length <= max_length`.
fn resolve_length(
    min_length: Option<u32>,
    max_length: Option<u32>,
) -> Result<u8, PasswordRulesError> {
    if let (Some(min), Some(max)) = (min_length, max_length)
        && min > max
    {
        return Err(PasswordRulesError::InvalidLength);
    }
    let min_u32 = MINIMUM_PASSWORD_LENGTH as u32;
    let max_u32 = MAXIMUM_PASSWORD_LENGTH as u32;
    let lower_bound = min_length.unwrap_or(0).clamp(min_u32, max_u32);
    let upper_bound = max_length.unwrap_or(max_u32).clamp(min_u32, max_u32);
    let clamped = DEFAULT_LENGTH.clamp(lower_bound, upper_bound);
    u8::try_from(clamped).map_err(|_| PasswordRulesError::InvalidLength)
}

/// Map the external parser's error into the SDK's `PasswordRulesError::Parse(String)`,
/// truncating the message so the payload stays bounded across FFI.
fn parse_error_to_sdk<E: std::fmt::Display>(e: E) -> PasswordRulesError {
    PasswordRulesError::Parse(truncate_for_error(&e.to_string()))
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;
    use crate::password::password_with_rng_for_test;

    #[test]
    fn parses_minlength() {
        let req = parse_password_rules("minlength: 12").unwrap();
        assert_eq!(req.length, 16);
        // Default classes when no `required`/`allowed` is given.
        assert!(req.lowercase && req.uppercase && req.numbers && req.special);
    }

    #[test]
    fn parses_maxlength_clamps_default_down() {
        let req = parse_password_rules("maxlength: 10").unwrap();
        assert_eq!(req.length, 10);
    }

    #[test]
    fn parses_minlength_clamps_default_up() {
        let req = parse_password_rules("minlength: 20").unwrap();
        assert_eq!(req.length, 20);
    }

    #[test]
    fn parses_minlength_clamps_to_max_password_length() {
        let req = parse_password_rules("minlength: 200").unwrap();
        assert_eq!(req.length, MAXIMUM_PASSWORD_LENGTH);
    }

    #[test]
    fn parses_minlength_with_maxlength_below_default() {
        let req = parse_password_rules("minlength: 5; maxlength: 8").unwrap();
        assert_eq!(req.length, 8);
    }

    #[test]
    fn parses_minlength_with_maxlength_at_default() {
        let req = parse_password_rules("minlength: 8").unwrap();
        assert_eq!(req.length, 16);
    }

    #[test]
    fn rejects_minlength_greater_than_maxlength() {
        let err = parse_password_rules("minlength: 20; maxlength: 10").unwrap_err();
        assert_eq!(err, PasswordRulesError::InvalidLength);
    }

    #[test]
    fn parses_max_consecutive() {
        let req = parse_password_rules("max-consecutive: 3").unwrap();
        assert_eq!(req.max_consecutive, Some(3));
    }

    #[test]
    fn parses_required_alone_defaults_allowed_to_required() {
        let req = parse_password_rules("required: upper").unwrap();
        assert!(req.uppercase);
        assert!(!req.lowercase);
        assert!(!req.numbers);
        assert!(!req.special);
        assert_eq!(req.min_uppercase, Some(1));
        assert_eq!(req.min_lowercase, None);
    }

    #[test]
    fn parses_allowed_alone() {
        let req = parse_password_rules("allowed: lower, digit").unwrap();
        assert!(req.lowercase);
        assert!(req.numbers);
        assert!(!req.uppercase);
        assert!(!req.special);
        assert_eq!(req.min_lowercase, None);
        assert_eq!(req.min_number, None);
    }

    #[test]
    fn parses_required_and_allowed_together() {
        let req = parse_password_rules("required: upper; allowed: lower, digit").unwrap();
        assert!(req.uppercase && req.lowercase && req.numbers);
        assert!(!req.special);
        assert_eq!(req.min_uppercase, Some(1));
        assert_eq!(req.min_lowercase, None);
    }

    #[test]
    fn empty_input_defaults_to_ascii_printable() {
        let req = parse_password_rules("").unwrap();
        assert!(req.lowercase && req.uppercase && req.numbers && req.special);
    }

    #[test]
    fn whitespace_only_input_defaults_to_ascii_printable() {
        let req = parse_password_rules("   \t  ").unwrap();
        assert!(req.lowercase && req.uppercase && req.numbers && req.special);
    }

    #[test]
    fn ascii_printable_enables_all_four_standard_classes() {
        let req = parse_password_rules("allowed: ascii-printable").unwrap();
        assert!(req.lowercase && req.uppercase && req.numbers && req.special);
    }

    #[test]
    fn unicode_keyword_enables_all_four_standard_classes() {
        let req = parse_password_rules("allowed: unicode").unwrap();
        assert!(req.lowercase && req.uppercase && req.numbers && req.special);
    }

    #[test]
    fn custom_class_dash_is_literal_when_first() {
        let req = parse_password_rules("required: [-abc]").unwrap();
        let chars = req.custom_required_chars.unwrap();
        let set: BTreeSet<char> = chars.chars().collect();
        assert_eq!(set, BTreeSet::from(['-', 'a', 'b', 'c']));
    }

    #[test]
    fn custom_class_bracket_is_literal_when_last() {
        let req = parse_password_rules("required: [abc]]").unwrap();
        let chars = req.custom_required_chars.unwrap();
        let set: BTreeSet<char> = chars.chars().collect();
        assert_eq!(set, BTreeSet::from(['a', 'b', 'c', ']']));
    }

    #[test]
    fn custom_class_dash_in_middle_is_error() {
        let err = parse_password_rules("required: [a-b]").unwrap_err();
        assert!(matches!(err, PasswordRulesError::Parse(_)));
    }

    #[test]
    fn custom_class_open_bracket_is_treated_as_literal() {
        // The external `password-rules-parser` crate accepts `[` as a literal char inside
        // a custom class, so `[abc[]` parses to the set `{'[', 'a', 'b', 'c'}` rather than
        // erroring. Documented behavior change vs. the previous in-tree parser.
        let req = parse_password_rules("required: [abc[]").unwrap();
        let chars = req.custom_required_chars.unwrap();
        let set: BTreeSet<char> = chars.chars().collect();
        assert_eq!(set, BTreeSet::from(['[', 'a', 'b', 'c']));
    }

    #[test]
    fn custom_class_drops_non_ascii_printable() {
        // 'é' and space are not ascii_graphic so the translation layer drops them.
        let req = parse_password_rules("required: [aéb c]").unwrap();
        let chars = req.custom_required_chars.unwrap();
        let set: BTreeSet<char> = chars.chars().collect();
        assert_eq!(set, BTreeSet::from(['a', 'b', 'c']));
    }

    #[test]
    fn whitespace_tolerance() {
        let a = parse_password_rules("  minlength : 8 ; required: upper  ").unwrap();
        let b = parse_password_rules("minlength:8;required:upper").unwrap();
        assert_eq!(a.length, b.length);
        assert_eq!(a.uppercase, b.uppercase);
        assert_eq!(a.min_uppercase, b.min_uppercase);
    }

    #[test]
    fn trailing_semicolon_accepted() {
        let req = parse_password_rules("required: upper;").unwrap();
        assert!(req.uppercase);
    }

    #[test]
    fn unknown_property_errors() {
        let err = parse_password_rules("zzz: 1").unwrap_err();
        assert!(matches!(err, PasswordRulesError::Parse(_)));
    }

    #[test]
    fn malformed_rule_missing_colon() {
        let err = parse_password_rules("minlength 8").unwrap_err();
        assert!(matches!(err, PasswordRulesError::Parse(_)));
    }

    #[test]
    fn invalid_numeric_value_errors() {
        let err = parse_password_rules("minlength: abc").unwrap_err();
        assert!(matches!(err, PasswordRulesError::Parse(_)));
    }

    #[test]
    fn property_name_matching_is_case_insensitive() {
        let mixed = parse_password_rules("MinLength: 8").unwrap();
        let lower = parse_password_rules("minlength: 8").unwrap();
        assert_eq!(mixed.length, lower.length);
    }

    #[test]
    fn required_property_name_matching_is_case_insensitive() {
        let mixed = parse_password_rules("REQUIRED: UPPER").unwrap();
        let lower = parse_password_rules("required: upper").unwrap();
        assert_eq!(mixed.uppercase, lower.uppercase);
        assert_eq!(mixed.min_uppercase, lower.min_uppercase);
    }

    #[test]
    fn class_keyword_matching_is_case_insensitive() {
        let mixed = parse_password_rules("allowed: Ascii-Printable").unwrap();
        let lower = parse_password_rules("allowed: ascii-printable").unwrap();
        assert_eq!(mixed.lowercase, lower.lowercase);
        assert_eq!(mixed.uppercase, lower.uppercase);
        assert_eq!(mixed.numbers, lower.numbers);
        assert_eq!(mixed.special, lower.special);
    }

    #[test]
    fn custom_class_contents_are_not_lowercased() {
        let req = parse_password_rules("required: [ABC]").unwrap();
        let chars = req.custom_required_chars.unwrap();
        let set: BTreeSet<char> = chars.chars().collect();
        assert_eq!(set, BTreeSet::from(['A', 'B', 'C']));
    }

    #[test]
    fn maxlength_below_minimum_clamps_up_to_floor() {
        let req = parse_password_rules("maxlength: 4").unwrap();
        assert_eq!(req.length, MINIMUM_PASSWORD_LENGTH);
    }

    #[test]
    fn maxlength_well_below_minimum_still_clamps_up_to_floor() {
        let req = parse_password_rules("maxlength: 3").unwrap();
        assert_eq!(req.length, MINIMUM_PASSWORD_LENGTH);
    }

    #[test]
    fn error_payloads_are_truncated() {
        let long = "a".repeat(MAX_ECHOED_VALUE_LEN + 50);
        let input = format!("{long}: 1");
        let err = parse_password_rules(&input).unwrap_err();
        match err {
            PasswordRulesError::Parse(s) => {
                assert!(s.chars().count() <= MAX_ECHOED_VALUE_LEN + 1);
                assert!(s.ends_with('…'));
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn generator_honors_custom_required_chars() {
        let req = parse_password_rules("required: [!@#]; minlength: 16").unwrap();
        assert_eq!(req.length, 16);
        let custom: BTreeSet<char> = req
            .custom_required_chars
            .as_deref()
            .unwrap()
            .chars()
            .collect();
        assert_eq!(custom, BTreeSet::from(['!', '@', '#']));

        let rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);
        let out = password_with_rng_for_test(rng, req).expect("password generation succeeds");
        let any_custom = out.chars().any(|c| c == '!' || c == '@' || c == '#');
        assert!(any_custom, "expected at least one of !@# in {out}");
    }
}
