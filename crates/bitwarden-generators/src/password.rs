use std::collections::BTreeSet;

use bitwarden_error::bitwarden_error;
use rand::{Rng, RngExt, distr::Distribution, seq::SliceRandom};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "wasm")]
use tsify::Tsify;

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("No character set enabled")]
    NoCharacterSetEnabled,
    #[error("Invalid password length")]
    InvalidLength,
}

/// Password generator request options.
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct PasswordGeneratorRequest {
    /// Include lowercase characters (a-z).
    pub lowercase: bool,
    /// Include uppercase characters (A-Z).
    pub uppercase: bool,
    /// Include numbers (0-9).
    pub numbers: bool,
    /// Include special characters: ! @ # $ % ^ & *
    pub special: bool,

    /// The length of the generated password.
    /// Note that the password length must be greater than the sum of all the minimums.
    pub length: u8,

    /// When set to true, the generated password will not contain ambiguous characters.
    /// The ambiguous characters are: I, O, l, 0, 1
    pub avoid_ambiguous: bool, // TODO: Should we rename this to include_all_characters?

    /// The minimum number of lowercase characters in the generated password.
    /// When set, the value must be between 1 and 9. This value is ignored if lowercase is false.
    pub min_lowercase: Option<u8>,
    /// The minimum number of uppercase characters in the generated password.
    /// When set, the value must be between 1 and 9. This value is ignored if uppercase is false.
    pub min_uppercase: Option<u8>,
    /// The minimum number of numbers in the generated password.
    /// When set, the value must be between 1 and 9. This value is ignored if numbers is false.
    pub min_number: Option<u8>,
    /// The minimum number of special characters in the generated password.
    /// When set, the value must be between 1 and 9. This value is ignored if special is false.
    pub min_special: Option<u8>,

    /// Custom characters that must each be available to the generator and from which at least
    /// one character is guaranteed to appear in the output. Each character of the string is
    /// treated as a member of the custom required set. Non-ASCII-printable characters are
    /// silently dropped during validation.
    ///
    /// This is primarily used by the HTML `passwordrules` parser to honor custom required
    /// character classes (e.g. `required: [!#$]`).
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub custom_required_chars: Option<String>,
    /// Custom characters that are added to the overall pool of allowed characters, but are not
    /// required to appear. Each character of the string is treated as a member of the custom
    /// allowed set. Non-ASCII-printable characters are silently dropped during validation.
    ///
    /// This is primarily used by the HTML `passwordrules` parser to honor custom allowed
    /// character classes (e.g. `allowed: [-_.]`).
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub custom_allowed_chars: Option<String>,

    /// The maximum number of consecutive identical characters allowed in the generated password,
    /// as expressed by the HTML `passwordrules` `max-consecutive` property. `None` disables
    /// the check; `Some(0)` is invalid and rejected at request validation. Enforced via
    /// re-shuffle with a single-pass repair fallback for degenerate pool sizes.
    #[cfg_attr(feature = "uniffi", uniffi(default = None))]
    #[cfg_attr(feature = "wasm", tsify(optional))]
    pub max_consecutive: Option<u8>,
}

const DEFAULT_PASSWORD_LENGTH: u8 = 16;

/// Minimum password length accepted by client-facing callers.
/// The SDK's internal validator allows shorter values, but all Bitwarden clients
/// silently clamp up to this value for entropy reasons.
pub const MINIMUM_PASSWORD_LENGTH: u8 = 5;
/// Maximum password length accepted by Bitwarden clients.
pub const MAXIMUM_PASSWORD_LENGTH: u8 = 128;
/// Minimum value for `min_number` / `min_special` (per-charset minimum count).
pub const MINIMUM_MIN_CHAR_COUNT: u8 = 0;
/// Maximum value for `min_number` / `min_special` (per-charset minimum count).
pub const MAXIMUM_MIN_CHAR_COUNT: u8 = 9;

impl Default for PasswordGeneratorRequest {
    fn default() -> Self {
        Self {
            lowercase: true,
            uppercase: true,
            numbers: true,
            special: false,
            length: DEFAULT_PASSWORD_LENGTH,
            avoid_ambiguous: false,
            min_lowercase: None,
            min_uppercase: None,
            min_number: None,
            min_special: None,
            custom_required_chars: None,
            custom_allowed_chars: None,
            max_consecutive: None,
        }
    }
}

/// Filters the characters of `s` down to ASCII-printable, non-whitespace, deduplicated
/// characters, preserving relative order on first occurrence.
fn sanitize_custom_chars(s: &str) -> Vec<char> {
    let mut seen = BTreeSet::new();
    s.chars()
        .filter(|c| c.is_ascii_graphic())
        .filter(|c| seen.insert(*c))
        .collect()
}

const UPPER_CHARS_AMBIGUOUS: &[char] = &['I', 'O'];
const LOWER_CHARS_AMBIGUOUS: &[char] = &['l'];
const NUMBER_CHARS_AMBIGUOUS: &[char] = &['0', '1'];
const SPECIAL_CHARS: &[char] = &['!', '@', '#', '$', '%', '^', '&', '*'];

/// A set of characters used to generate a password. This set is backed by a BTreeSet
/// to have consistent ordering between runs. This is not important during normal execution,
/// but it's necessary for the tests to be repeatable.
/// To create an instance, use [`CharSet::default()`](CharSet::default)
#[derive(Clone, Default)]
struct CharSet(BTreeSet<char>);
impl CharSet {
    /// Includes the given characters in the set. Any duplicate items will be ignored
    pub fn include(self, other: impl IntoIterator<Item = char>) -> Self {
        self.include_if(true, other)
    }

    /// Includes the given characters in the set if the predicate is true. Any duplicate items will
    /// be ignored
    pub fn include_if(mut self, predicate: bool, other: impl IntoIterator<Item = char>) -> Self {
        if predicate {
            self.0.extend(other);
        }
        self
    }

    /// Excludes the given characters from the set. Any missing items will be ignored
    pub fn exclude_if<'a>(
        self,
        predicate: bool,
        other: impl IntoIterator<Item = &'a char>,
    ) -> Self {
        if predicate {
            let other: BTreeSet<_> = other.into_iter().copied().collect();
            Self(self.0.difference(&other).copied().collect())
        } else {
            self
        }
    }
}
impl<'a> IntoIterator for &'a CharSet {
    type Item = char;
    type IntoIter = std::iter::Copied<std::collections::btree_set::Iter<'a, char>>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter().copied()
    }
}
impl Distribution<char> for CharSet {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> char {
        let idx = rng.random_range(0..self.0.len());
        *self.0.iter().nth(idx).expect("Valid index")
    }
}

/// Represents a set of valid options to generate a password with.
/// To get an instance of it, use
/// [`PasswordGeneratorRequest::validate_options`](PasswordGeneratorRequest::validate_options)
struct PasswordGeneratorOptions {
    lower: (CharSet, usize),
    upper: (CharSet, usize),
    number: (CharSet, usize),
    special: (CharSet, usize),
    /// Custom required characters from `passwordrules` `required: [...]` entries. At least one
    /// char from this set is guaranteed to appear in the output when the set is non-empty.
    custom: (CharSet, usize),
    all: (CharSet, usize),

    length: usize,

    /// Maximum number of consecutive identical characters allowed in the output. `None`
    /// disables the check. Validated to be `>= 1` in
    /// [`PasswordGeneratorRequest::validate_options`].
    max_consecutive: Option<usize>,
}

impl PasswordGeneratorRequest {
    /// Validates the request and returns an immutable struct with valid options to use with the
    /// password generator.
    fn validate_options(self) -> Result<PasswordGeneratorOptions, PasswordError> {
        // TODO: Add password generator policy checks

        // Sanitize custom char lists defensively: the parser already filters non-printable
        // characters, but the request type is `pub` so callers can construct it directly.
        let custom_required = self
            .custom_required_chars
            .as_deref()
            .map(sanitize_custom_chars)
            .unwrap_or_default();
        let custom_allowed: Vec<char> = self
            .custom_allowed_chars
            .as_deref()
            .map(sanitize_custom_chars)
            .unwrap_or_default();

        // We always have to have at least one character set enabled (standard or custom).
        if !self.lowercase
            && !self.uppercase
            && !self.numbers
            && !self.special
            && custom_required.is_empty()
            && custom_allowed.is_empty()
        {
            return Err(PasswordError::NoCharacterSetEnabled);
        }

        if self.length < 4 {
            return Err(PasswordError::InvalidLength);
        }

        // Make sure the minimum values are zero when the character
        // set is disabled, and at least one when it's enabled
        fn get_minimum(min: Option<u8>, enabled: bool) -> usize {
            if enabled {
                usize::max(min.unwrap_or(1) as usize, 1)
            } else {
                0
            }
        }

        let length = self.length as usize;
        let min_lowercase = get_minimum(self.min_lowercase, self.lowercase);
        let min_uppercase = get_minimum(self.min_uppercase, self.uppercase);
        let min_number = get_minimum(self.min_number, self.numbers);
        let min_special = get_minimum(self.min_special, self.special);
        let min_custom = if custom_required.is_empty() { 0 } else { 1 };

        // Check that the minimum lengths aren't larger than the password length
        let minimum_length = min_lowercase + min_uppercase + min_number + min_special + min_custom;
        if minimum_length > length {
            return Err(PasswordError::InvalidLength);
        }

        let lower = (
            CharSet::default()
                .include_if(self.lowercase, 'a'..='z')
                .exclude_if(self.avoid_ambiguous, LOWER_CHARS_AMBIGUOUS),
            min_lowercase,
        );

        let upper = (
            CharSet::default()
                .include_if(self.uppercase, 'A'..='Z')
                .exclude_if(self.avoid_ambiguous, UPPER_CHARS_AMBIGUOUS),
            min_uppercase,
        );

        let number = (
            CharSet::default()
                .include_if(self.numbers, '0'..='9')
                .exclude_if(self.avoid_ambiguous, NUMBER_CHARS_AMBIGUOUS),
            min_number,
        );

        let special = (
            CharSet::default().include_if(self.special, SPECIAL_CHARS.iter().copied()),
            min_special,
        );

        let custom = (
            CharSet::default().include(custom_required.iter().copied()),
            min_custom,
        );

        let all = (
            CharSet::default()
                .include(&lower.0)
                .include(&upper.0)
                .include(&number.0)
                .include(&special.0)
                .include(&custom.0)
                .include(custom_allowed.iter().copied()),
            length - minimum_length,
        );

        // A `max_consecutive` of 0 would forbid every output (no character can appear once
        // without exceeding a run of 0). Reject it up front so the generator can assume any
        // populated `Some(_)` is `>= 1`.
        let max_consecutive = match self.max_consecutive {
            None => None,
            Some(0) => return Err(PasswordError::InvalidLength),
            Some(n) => Some(n as usize),
        };

        Ok(PasswordGeneratorOptions {
            lower,
            upper,
            number,
            special,
            custom,
            all,
            length,
            max_consecutive,
        })
    }
}

/// Implementation of the random password generator.
pub(crate) fn password(input: PasswordGeneratorRequest) -> Result<String, PasswordError> {
    let options = input.validate_options()?;
    Ok(password_with_rng(rand::rng(), options))
}

/// Test-only helper that validates a request and runs the generator with a caller-supplied RNG.
/// Lets the `passwordrules` test module exercise the end-to-end generator path deterministically.
#[cfg(test)]
pub(crate) fn password_with_rng_for_test(
    rng: impl Rng,
    input: PasswordGeneratorRequest,
) -> Result<String, PasswordError> {
    let options = input.validate_options()?;
    Ok(password_with_rng(rng, options))
}

fn password_with_rng(mut rng: impl Rng, options: PasswordGeneratorOptions) -> String {
    let mut buf: Vec<char> = Vec::with_capacity(options.length);

    let opts = [
        &options.all,
        &options.upper,
        &options.lower,
        &options.number,
        &options.special,
        &options.custom,
    ];
    for (set, qty) in opts {
        buf.extend(set.sample_iter(&mut rng).take(*qty));
    }

    buf.shuffle(&mut rng);

    if let Some(limit) = options.max_consecutive {
        // For realistic inputs (length up to 128, charset size > limit) a re-shuffle clears
        // the violation in a few rounds. The repair-pass fallback handles pathological cases
        // (small charset, large length) where re-shuffles wouldn't terminate quickly.
        const MAX_RESHUFFLES: u8 = 16;
        let mut tries = 0;
        while violates_max_consecutive(&buf, limit) && tries < MAX_RESHUFFLES {
            buf.shuffle(&mut rng);
            tries += 1;
        }
        if violates_max_consecutive(&buf, limit) {
            repair_consecutive(&mut buf, limit);
        }
    }

    buf.iter().collect()
}

/// Returns `true` if `buf` contains a run of identical characters longer than `limit`.
fn violates_max_consecutive(buf: &[char], limit: usize) -> bool {
    if limit == 0 || buf.len() <= limit {
        return false;
    }
    let mut run = 1usize;
    for w in buf.windows(2) {
        if w[0] == w[1] {
            run += 1;
            if run > limit {
                return true;
            }
        } else {
            run = 1;
        }
    }
    false
}

/// Single-pass repair: scans `buf` and, whenever a run grows past `limit`, swaps the
/// offending character with the next non-matching character ahead in the buffer. Used
/// only when re-shuffling fails to clear the constraint (typically when the available
/// pool is degenerately small relative to the requested length).
fn repair_consecutive(buf: &mut [char], limit: usize) {
    if limit == 0 || buf.len() <= limit {
        return;
    }
    let mut run = 1usize;
    let mut i = 1;
    while i < buf.len() {
        if buf[i] == buf[i - 1] {
            run += 1;
            if run > limit {
                // Find any later position with a character that breaks both the current
                // run and the trailing run (so we don't extend a different violation).
                let target = (i + 1..buf.len())
                    .find(|&k| buf[k] != buf[i] && (k + 1 == buf.len() || buf[k + 1] != buf[i]));
                match target {
                    Some(j) => {
                        buf.swap(i, j);
                        run = 1;
                    }
                    None => {
                        // No feasible swap target; leave the constraint partially satisfied
                        // rather than looping. For realistic inputs (any charset of size >=2
                        // with charset_size >> length / limit) this branch is unreachable.
                        return;
                    }
                }
            }
        } else {
            run = 1;
        }
        i += 1;
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;

    use rand::SeedableRng;

    use super::*;

    // We convert the slices to BTreeSets to be able to use `is_subset`
    fn ref_to_set<'a>(chars: impl IntoIterator<Item = &'a char>) -> BTreeSet<char> {
        chars.into_iter().copied().collect()
    }
    fn to_set(chars: impl IntoIterator<Item = char>) -> BTreeSet<char> {
        chars.into_iter().collect()
    }

    #[test]
    fn test_password_gen_all_charsets_enabled() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);

        let options = PasswordGeneratorRequest {
            lowercase: true,
            uppercase: true,
            numbers: true,
            special: true,
            avoid_ambiguous: false,
            ..Default::default()
        }
        .validate_options()
        .unwrap();

        assert_eq!(to_set(&options.lower.0), to_set('a'..='z'));
        assert_eq!(to_set(&options.upper.0), to_set('A'..='Z'));
        assert_eq!(to_set(&options.number.0), to_set('0'..='9'));
        assert_eq!(to_set(&options.special.0), ref_to_set(SPECIAL_CHARS));

        let pass = password_with_rng(&mut rng, options);
        assert_eq!(pass, "0oA772tQjaUO$a@L");
    }

    #[test]
    fn test_password_gen_only_letters_enabled() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);

        let options = PasswordGeneratorRequest {
            lowercase: true,
            uppercase: true,
            numbers: false,
            special: false,
            avoid_ambiguous: false,
            ..Default::default()
        }
        .validate_options()
        .unwrap();

        assert_eq!(to_set(&options.lower.0), to_set('a'..='z'));
        assert_eq!(to_set(&options.upper.0), to_set('A'..='Z'));
        assert_eq!(to_set(&options.number.0), to_set([]));
        assert_eq!(to_set(&options.special.0), to_set([]));

        let pass = password_with_rng(&mut rng, options);
        assert_eq!(pass, "FrNSJGvhnAbXggMU");
    }

    #[test]
    fn test_password_gen_only_numbers_and_lower_enabled_no_ambiguous() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);

        let options = PasswordGeneratorRequest {
            lowercase: true,
            uppercase: false,
            numbers: true,
            special: false,
            avoid_ambiguous: true,
            ..Default::default()
        }
        .validate_options()
        .unwrap();

        assert!(to_set(&options.lower.0).is_subset(&to_set('a'..='z')));
        assert!(to_set(&options.lower.0).is_disjoint(&ref_to_set(LOWER_CHARS_AMBIGUOUS)));

        assert!(to_set(&options.number.0).is_subset(&to_set('0'..='9')));
        assert!(to_set(&options.number.0).is_disjoint(&ref_to_set(NUMBER_CHARS_AMBIGUOUS)));

        assert_eq!(to_set(&options.upper.0), to_set([]));
        assert_eq!(to_set(&options.special.0), to_set([]));

        let pass = password_with_rng(&mut rng, options);
        assert_eq!(pass, "5uat85wos2jg4n9f");
    }

    #[test]
    fn test_password_gen_only_upper_and_special_enabled_no_ambiguous() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);

        let options = PasswordGeneratorRequest {
            lowercase: false,
            uppercase: true,
            numbers: false,
            special: true,
            avoid_ambiguous: true,
            ..Default::default()
        }
        .validate_options()
        .unwrap();

        assert!(to_set(&options.upper.0).is_subset(&to_set('A'..='Z')));
        assert!(to_set(&options.upper.0).is_disjoint(&ref_to_set(UPPER_CHARS_AMBIGUOUS)));

        assert_eq!(to_set(&options.special.0), ref_to_set(SPECIAL_CHARS));

        assert_eq!(to_set(&options.lower.0), to_set([]));
        assert_eq!(to_set(&options.number.0), to_set([]));

        let pass = password_with_rng(&mut rng, options);
        assert_eq!(pass, "%VBT*%YPT!LH$PAF");
    }

    #[test]
    fn test_password_gen_minimum_limits() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);

        let options = PasswordGeneratorRequest {
            lowercase: true,
            uppercase: true,
            numbers: true,
            special: true,
            avoid_ambiguous: false,
            length: 24,
            min_lowercase: Some(5),
            min_uppercase: Some(5),
            min_number: Some(5),
            min_special: Some(5),
            ..Default::default()
        }
        .validate_options()
        .unwrap();

        assert_eq!(to_set(&options.lower.0), to_set('a'..='z'));
        assert_eq!(to_set(&options.upper.0), to_set('A'..='Z'));
        assert_eq!(to_set(&options.number.0), to_set('0'..='9'));
        assert_eq!(to_set(&options.special.0), ref_to_set(SPECIAL_CHARS));

        assert_eq!(options.lower.1, 5);
        assert_eq!(options.upper.1, 5);
        assert_eq!(options.number.1, 5);
        assert_eq!(options.special.1, 5);

        let pass = password_with_rng(&mut rng, options);
        assert_eq!(pass, "t&c0L73*D*G%aak7goq!N2T4");
    }

    fn longest_run(s: &str) -> usize {
        let mut longest = 0usize;
        let mut run = 0usize;
        let mut prev: Option<char> = None;
        for c in s.chars() {
            if prev == Some(c) {
                run += 1;
            } else {
                run = 1;
                prev = Some(c);
            }
            longest = longest.max(run);
        }
        longest
    }

    #[test]
    fn test_password_gen_honors_max_consecutive() {
        // 64 attempts at length 64 across ascii-printable: even ignoring our enforcement,
        // ambient runs of 4 should be vanishingly rare. With the constraint enforced
        // (max_consecutive: 2) every iteration must satisfy run-length <= 2.
        for seed_byte in 0u8..64 {
            let mut rng = rand_chacha::ChaCha8Rng::from_seed([seed_byte; 32]);
            let options = PasswordGeneratorRequest {
                lowercase: true,
                uppercase: true,
                numbers: true,
                special: true,
                avoid_ambiguous: false,
                length: 64,
                max_consecutive: Some(2),
                ..Default::default()
            }
            .validate_options()
            .unwrap();
            let pass = password_with_rng(&mut rng, options);
            let run = longest_run(&pass);
            assert!(
                run <= 2,
                "seed={seed_byte}: produced {pass:?} with run of length {run} (>2)"
            );
        }
    }

    #[test]
    fn test_password_gen_max_consecutive_one_breaks_pairs() {
        // The tightest meaningful constraint: no two adjacent characters may be equal.
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([7u8; 32]);
        let options = PasswordGeneratorRequest {
            lowercase: true,
            uppercase: true,
            numbers: true,
            special: true,
            avoid_ambiguous: false,
            length: 32,
            max_consecutive: Some(1),
            ..Default::default()
        }
        .validate_options()
        .unwrap();
        let pass = password_with_rng(&mut rng, options);
        assert!(
            longest_run(&pass) <= 1,
            "produced {pass:?} with adjacent duplicate"
        );
    }

    #[test]
    fn test_password_gen_max_consecutive_zero_is_rejected() {
        let result = PasswordGeneratorRequest {
            lowercase: true,
            length: 14,
            max_consecutive: Some(0),
            ..Default::default()
        }
        .validate_options();
        assert!(
            matches!(result, Err(PasswordError::InvalidLength)),
            "expected InvalidLength for max_consecutive=Some(0)"
        );
    }

    #[test]
    fn test_password_gen_max_consecutive_none_is_unconstrained() {
        // Sanity: explicit None and Default's None should behave identically (no constraint).
        let mut rng_a = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);
        let mut rng_b = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);
        let opts_a = PasswordGeneratorRequest {
            lowercase: true,
            uppercase: true,
            numbers: true,
            special: true,
            avoid_ambiguous: false,
            ..Default::default()
        }
        .validate_options()
        .unwrap();
        let opts_b = PasswordGeneratorRequest {
            lowercase: true,
            uppercase: true,
            numbers: true,
            special: true,
            avoid_ambiguous: false,
            max_consecutive: None,
            ..Default::default()
        }
        .validate_options()
        .unwrap();
        assert_eq!(
            password_with_rng(&mut rng_a, opts_a),
            password_with_rng(&mut rng_b, opts_b)
        );
    }
}
