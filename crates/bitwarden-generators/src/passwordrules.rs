//! Parser for the HTML `passwordrules` attribute.
//!
//! Reference: Apple's [password-manager-resources spec][apple-spec] (also a WHATWG proposal).
//! The grammar is:
//!
//! ```text
//! rules    = rule *( ";" rule )           ; whitespace around rules is allowed
//! rule     = property ":" value
//! property = "minlength" | "maxlength" | "required" | "allowed" | "max-consecutive"
//! value    = digits  (for minlength / maxlength / max-consecutive)
//!          | classlist  (for required / allowed; comma-separated)
//! classname = "upper" | "lower" | "digit" | "special" | "ascii-printable" | "unicode" | custom
//! custom    = "[" literal-chars "]"
//! ```
//!
//! The parser converts the rule string into a [`PasswordGeneratorRequest`] that the SDK's
//! password generator can satisfy.
//!
//! [apple-spec]: https://github.com/apple/password-manager-resources

use std::collections::BTreeSet;

use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::password::{MAXIMUM_PASSWORD_LENGTH, MINIMUM_PASSWORD_LENGTH, PasswordGeneratorRequest};

/// Errors that may occur while parsing an HTML `passwordrules` attribute.
#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PasswordRulesError {
    /// A rule referenced a property name not listed in the spec.
    #[error("Unknown property: {0}")]
    UnknownProperty(String),
    /// A rule's value did not match the expected form for its property
    /// (e.g. non-numeric digits, unknown class name).
    #[error("Invalid value for property '{property}': {value}")]
    InvalidValue {
        /// The property whose value was rejected.
        property: String,
        /// The offending value (truncated/redacted where appropriate).
        value: String,
    },
    /// A custom class (`[...]`) was malformed (unterminated, illegally placed `-` or `]`).
    #[error("Malformed custom character class: {0}")]
    MalformedCustomClass(String),
    /// `minlength` exceeds `maxlength`, or a length value is out of range for a `u32`.
    #[error("Invalid length constraint")]
    InvalidLength,
    /// A rule did not contain a `:` separator.
    #[error("Malformed rule: missing ':' separator")]
    MalformedRule,
}

/// Default password length used when no `minlength`/`maxlength` constrains the choice.
/// Matches the SDK's default in [`PasswordGeneratorRequest::default`].
const DEFAULT_LENGTH: u32 = 16;

/// Maximum length (in characters) of any user-supplied substring echoed back in error variants.
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

/// The set of standard character classes that may appear in `required` / `allowed` rules.
#[derive(Default, Debug, Clone)]
struct ParsedClasses {
    upper: bool,
    lower: bool,
    digit: bool,
    special: bool,
    /// Literal ASCII-printable characters from one or more custom `[...]` classes.
    custom: BTreeSet<char>,
}

impl ParsedClasses {
    fn is_empty(&self) -> bool {
        !self.upper && !self.lower && !self.digit && !self.special && self.custom.is_empty()
    }

    fn merge(&mut self, other: &ParsedClasses) {
        self.upper |= other.upper;
        self.lower |= other.lower;
        self.digit |= other.digit;
        self.special |= other.special;
        self.custom.extend(other.custom.iter().copied());
    }
}

/// Parses an HTML `passwordrules` attribute string into a [`PasswordGeneratorRequest`].
///
/// Empty or whitespace-only input is accepted and resolves to the spec default
/// (`allowed: ascii-printable`).
pub fn parse_password_rules(rules: &str) -> Result<PasswordGeneratorRequest, PasswordRulesError> {
    let mut minlength: Option<u32> = None;
    let mut maxlength: Option<u32> = None;
    let mut max_consecutive: Option<u32> = None;
    let mut required = ParsedClasses::default();
    let mut allowed = ParsedClasses::default();
    let mut allowed_seen = false;

    for raw_rule in rules.split(';') {
        let rule = raw_rule.trim();
        if rule.is_empty() {
            continue;
        }

        let (property, value) = split_rule(rule)?;
        let property = property.trim();
        let value = value.trim();
        // Apple's reference parser lowercases property names before matching, so accept any
        // mixed-case spelling (`MinLength`, `REQUIRED`, etc.). Class keywords are lowercased
        // separately in `apply_keyword`; custom-class contents inside `[...]` are NOT lowercased.
        let property_lc = property.to_ascii_lowercase();

        match property_lc.as_str() {
            "minlength" => {
                minlength = Some(parse_u32(property, value)?);
            }
            "maxlength" => {
                maxlength = Some(parse_u32(property, value)?);
            }
            "max-consecutive" => {
                max_consecutive = Some(parse_u32(property, value)?);
            }
            "required" => {
                let classes = parse_classlist(property, value)?;
                required.merge(&classes);
            }
            "allowed" => {
                let classes = parse_classlist(property, value)?;
                allowed.merge(&classes);
                allowed_seen = true;
            }
            _ => {
                return Err(PasswordRulesError::UnknownProperty(truncate_for_error(
                    property,
                )));
            }
        }
    }

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

    // Validate length bounds against the raw user-supplied values BEFORE clamping, so an
    // inverted `minlength > maxlength` still surfaces as an error even when both values would
    // be clamped to the same SDK-supported bound.
    if let (Some(min), Some(max)) = (minlength, maxlength)
        && min > max
    {
        return Err(PasswordRulesError::InvalidLength);
    }

    // The union of allowed + required determines which standard classes are enabled in the
    // generator. Required classes also drive the min-count fields.
    let lowercase = allowed.lower || required.lower;
    let uppercase = allowed.upper || required.upper;
    let numbers = allowed.digit || required.digit;
    let special = allowed.special || required.special;

    // Custom char pools: required chars from required rules; allowed pool unions everything
    // custom we've seen. The generator treats `custom_allowed_chars` as additions to the
    // overall pool, and `custom_required_chars` as a "force one of these" set.
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

    // Length: start from the SDK default and clamp into the parsed bounds. Both bounds are
    // additionally clamped into [`MINIMUM_PASSWORD_LENGTH`, `MAXIMUM_PASSWORD_LENGTH`] — the
    // entropy floor enforced by every Bitwarden client (`MINIMUM_PASSWORD_LENGTH`) and the
    // SDK's hard upper bound. This guarantees `min <= max` before `clamp` (which panics on
    // an inverted range) and matches the behavior of `bw`'s password subcommand.
    let min_u32 = MINIMUM_PASSWORD_LENGTH as u32;
    let max_u32 = MAXIMUM_PASSWORD_LENGTH as u32;
    let lower_bound = minlength.unwrap_or(0).clamp(min_u32, max_u32);
    let upper_bound = maxlength.unwrap_or(max_u32).clamp(min_u32, max_u32);
    let clamped = DEFAULT_LENGTH.clamp(lower_bound, upper_bound);
    let length = u8::try_from(clamped).map_err(|_| PasswordRulesError::InvalidLength)?;

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

/// Splits a single rule on the first `:` into (property, value).
fn split_rule(rule: &str) -> Result<(&str, &str), PasswordRulesError> {
    rule.split_once(':')
        .ok_or(PasswordRulesError::MalformedRule)
}

/// Parses a `u32` value, returning an [`InvalidValue`] error on failure.
fn parse_u32(property: &str, value: &str) -> Result<u32, PasswordRulesError> {
    value
        .parse::<u32>()
        .map_err(|_| PasswordRulesError::InvalidValue {
            property: truncate_for_error(property),
            value: truncate_for_error(value),
        })
}

/// Parses a comma-separated class list, handling the spec-defined keywords and
/// bracketed custom character classes.
fn parse_classlist(property: &str, value: &str) -> Result<ParsedClasses, PasswordRulesError> {
    let mut classes = ParsedClasses::default();

    // The value is logically a comma-separated list, but custom classes (`[...]`) contain
    // literal characters that may themselves include commas. We therefore tokenize manually
    // rather than calling `split(',')`.
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip whitespace and commas between tokens.
        while i < bytes.len() && (bytes[i] == b',' || bytes[i].is_ascii_whitespace()) {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        if bytes[i] == b'[' {
            // Custom class — find the matching closing bracket.
            let start = i + 1;
            let end = bytes[start..]
                .iter()
                .position(|&b| b == b']')
                .map(|p| start + p)
                .ok_or_else(|| {
                    PasswordRulesError::MalformedCustomClass(format!(
                        "unterminated '[' in {property}"
                    ))
                })?;
            // The grammar permits `]` as the final literal char when written as `[abc]]`: an
            // empty class is the first `]`. To allow this, look ahead: if the next non-`]`
            // closes the token, treat the *last* `]` of a run as the terminator.
            //
            // In practice: scan forward from `start` to find the first `]`. If the char *after*
            // that `]` is also `]`, then the inner `]` is a literal and the outer one closes the
            // class. This implements the "`]` is literal only when it is the last char before the
            // closing `]`" rule.
            let (literal_end, close_idx) = if end + 1 < bytes.len() && bytes[end + 1] == b']' {
                // The first `]` is a literal at the end of the literal-chars region.
                (end + 1, end + 1)
            } else {
                (end, end)
            };

            // Safety: `start` and `literal_end` are byte offsets derived from positions of ASCII
            // bytes (`[` / `]`) inside `value`; any multi-byte UTF-8 sequence lives entirely
            // between such boundaries, so this byte-slice is valid UTF-8.
            #[allow(clippy::string_slice)]
            let literal_slice = &value[start..literal_end];
            let parsed = parse_custom_literal(literal_slice)?;
            classes.custom.extend(parsed);
            i = close_idx + 1;
            continue;
        }

        // Otherwise, scan until next `,` to extract a keyword.
        let token_end = bytes[i..]
            .iter()
            .position(|&b| b == b',')
            .map(|p| i + p)
            .unwrap_or(bytes.len());
        // Safety: `i` and `token_end` are byte offsets derived from positions of ASCII bytes
        // (`,` / current scan position past ASCII whitespace); see above.
        #[allow(clippy::string_slice)]
        let token = value[i..token_end].trim();
        if !token.is_empty() {
            apply_keyword(property, token, &mut classes)?;
        }
        i = token_end;
    }

    Ok(classes)
}

/// Applies a single class keyword (`upper`, `lower`, `digit`, `special`, `ascii-printable`,
/// `unicode`) to the given [`ParsedClasses`]. Matching is case-insensitive to mirror Apple's
/// reference parser.
fn apply_keyword(
    property: &str,
    keyword: &str,
    classes: &mut ParsedClasses,
) -> Result<(), PasswordRulesError> {
    match keyword.to_ascii_lowercase().as_str() {
        "upper" => classes.upper = true,
        "lower" => classes.lower = true,
        "digit" => classes.digit = true,
        "special" => classes.special = true,
        // The spec defines `ascii-printable` and `unicode` as broad classes; per the agreed
        // design, both enable all four standard classes.
        "ascii-printable" | "unicode" => {
            classes.upper = true;
            classes.lower = true;
            classes.digit = true;
            classes.special = true;
        }
        _ => {
            return Err(PasswordRulesError::InvalidValue {
                property: truncate_for_error(property),
                value: truncate_for_error(keyword),
            });
        }
    }
    Ok(())
}

/// Parses the literal-chars region of a custom class. Applies the spec's positional rules:
///   - `-` is a literal **only** when it is the first char after `[`.
///   - `]` is a literal **only** when it is the last char before the closing `]`.
///   - Otherwise, `-` or `]` are reserved and produce a parse error.
///   - Non-ASCII-printable characters are silently dropped.
fn parse_custom_literal(s: &str) -> Result<Vec<char>, PasswordRulesError> {
    let chars: Vec<char> = s.chars().collect();
    let mut out: Vec<char> = Vec::with_capacity(chars.len());

    let last_idx = chars.len().saturating_sub(1);
    for (idx, &c) in chars.iter().enumerate() {
        match c {
            '-' => {
                if idx == 0 {
                    out.push('-');
                } else {
                    return Err(PasswordRulesError::MalformedCustomClass(
                        "'-' is only valid as the first character of a custom class".to_string(),
                    ));
                }
            }
            ']' => {
                if idx == last_idx {
                    out.push(']');
                } else {
                    return Err(PasswordRulesError::MalformedCustomClass(
                        "']' is only valid as the last character of a custom class".to_string(),
                    ));
                }
            }
            '[' => {
                // `[` inside a custom class is not addressed explicitly by the spec; treat it
                // as a malformed class to avoid silently accepting nested-bracket input.
                return Err(PasswordRulesError::MalformedCustomClass(
                    "'[' is not allowed inside a custom class".to_string(),
                ));
            }
            other if crate::password::is_ascii_printable_non_whitespace(other) => out.push(other),
            // Silently drop non-ASCII-printable / whitespace chars per the spec.
            _ => {}
        }
    }

    Ok(out)
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
        // No `required`, so no min-counts.
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
        assert!(matches!(err, PasswordRulesError::MalformedCustomClass(_)));
    }

    #[test]
    fn custom_class_nested_open_bracket_is_error() {
        let err = parse_password_rules("required: [abc[]").unwrap_err();
        assert!(matches!(err, PasswordRulesError::MalformedCustomClass(_)));
    }

    #[test]
    fn custom_class_drops_non_ascii_printable() {
        // The 'é' and the space are both non-printable-ASCII-graphic and should be dropped.
        // Note: space is not ascii_graphic so it gets dropped too.
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
        assert_eq!(err, PasswordRulesError::UnknownProperty("zzz".to_string()));
    }

    #[test]
    fn malformed_rule_missing_colon() {
        let err = parse_password_rules("minlength 8").unwrap_err();
        assert_eq!(err, PasswordRulesError::MalformedRule);
    }

    #[test]
    fn invalid_numeric_value_errors() {
        let err = parse_password_rules("minlength: abc").unwrap_err();
        assert!(matches!(err, PasswordRulesError::InvalidValue { .. }));
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
        // The literal `A`/`B`/`C` inside `[...]` must be preserved verbatim, not folded to
        // lowercase by the property/keyword case-folding.
        let req = parse_password_rules("required: [ABC]").unwrap();
        let chars = req.custom_required_chars.unwrap();
        let set: BTreeSet<char> = chars.chars().collect();
        assert_eq!(set, BTreeSet::from(['A', 'B', 'C']));
    }

    #[test]
    fn maxlength_below_minimum_clamps_up_to_floor() {
        // `maxlength: 4` is below MINIMUM_PASSWORD_LENGTH (5), so the resolved length must
        // be clamped up to the floor rather than producing a sub-floor password.
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
        // Build a property name far longer than MAX_ECHOED_VALUE_LEN and assert that the
        // resulting error's payload is truncated with the ellipsis marker. Truncation must
        // operate on char boundaries — the trailing ellipsis itself is multi-byte.
        let long = "a".repeat(MAX_ECHOED_VALUE_LEN + 50);
        let input = format!("{long}: 1");
        let err = parse_password_rules(&input).unwrap_err();
        match err {
            PasswordRulesError::UnknownProperty(s) => {
                assert!(s.chars().count() <= MAX_ECHOED_VALUE_LEN + 1);
                assert!(s.ends_with('…'));
            }
            other => panic!("expected UnknownProperty, got {other:?}"),
        }
    }

    #[test]
    fn generator_honors_custom_required_chars() {
        // Parse a rule containing a custom required class, then assert at least one of the
        // custom chars appears in the generated output. Uses a fixed seed for determinism.
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
