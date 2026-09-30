//! Regular-expression URI matching with bounded pattern size and execution time, using the
//! linear-time [`regex`] crate. The one lookaround supported is a negative lookahead right after an
//! anchored literal prefix, `^literal(?!excluded)rest`, which is evaluated as two plain regexes.

use bitwarden_error::bitwarden_error;
use chrono::{TimeDelta, Utc};
use regex::{Regex, RegexBuilder};
use regex_syntax::ast::{self, Ast};
use serde::Serialize;
use thiserror::Error;
#[cfg(feature = "wasm")]
use {tsify::Tsify, wasm_bindgen::prelude::*};

/// Maximum accepted pattern length, in characters.
pub const MAX_PATTERN_LENGTH: usize = 1_000;

/// Maximum target length, in bytes, that patterns are evaluated against.
pub const MAX_TARGET_LENGTH: usize = 4_096;

/// Approximate compiled size limit for each regex.
const SIZE_LIMIT: usize = 1 << 20;
/// Approximate lazy DFA cache size for each regex.
const DFA_SIZE_LIMIT: usize = 1 << 20;
/// Time after which [`uri_regex_matches_batch`] stops evaluating further patterns.
const BATCH_TIME_BUDGET: TimeDelta = TimeDelta::milliseconds(100);

/// Reasons a regular-expression URI pattern cannot be used. Messages never include the pattern or
/// target, since both are vault data.
#[bitwarden_error(flat)]
#[derive(Debug, Clone, Error)]
pub enum UriMatcherError {
    /// The pattern is longer than [`MAX_PATTERN_LENGTH`].
    #[error("Pattern exceeds the maximum length")]
    PatternTooLong,
    /// The pattern is not a valid regular expression.
    #[error("Pattern is not a valid regular expression")]
    InvalidPattern,
    /// The pattern compiles too large or nests too deeply.
    #[error("Pattern is too complex")]
    PatternTooComplex,
    /// The pattern uses a backreference, a lookbehind, or a lookahead other than one right after
    /// an anchored literal prefix, as in `^https://(?!admin\.)`.
    #[error("Pattern uses an unsupported construct")]
    UnsupportedConstruct,
    /// The target is longer than [`MAX_TARGET_LENGTH`].
    #[error("Target exceeds the maximum length")]
    TargetTooLong,
}

/// Outcome of one pattern in [`uri_regex_matches_batch`].
#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum UriMatchStatus {
    /// The pattern matches the target.
    Match,
    /// The pattern doesn't match the target, or is invalid, oversized, or unsupported.
    NoMatch,
    /// The time budget ran out before the pattern was evaluated. Pass it to another call.
    Skipped,
}

/// Results of [`uri_regex_matches_batch`], one per pattern in input order.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi))]
#[serde(transparent)]
pub struct UriMatchResults(
    #[cfg_attr(feature = "wasm", tsify(type = "UriMatchStatus[]"))] pub Vec<UriMatchStatus>,
);

/// Returns whether `target` matches `pattern`, case-insensitively. Invalid, oversized, and
/// unsupported patterns never match.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn uri_regex_matches(pattern: &str, target: &str) -> bool {
    try_uri_regex_match(pattern, target).unwrap_or(false)
}

/// Like [`uri_regex_matches`], but reports why a pattern could not be evaluated.
pub fn try_uri_regex_match(pattern: &str, target: &str) -> Result<bool, UriMatcherError> {
    if target.len() > MAX_TARGET_LENGTH {
        return Err(UriMatcherError::TargetTooLong);
    }
    Ok(compile(pattern)?.is_match(target))
}

/// Evaluates each pattern against `target`, one result per pattern, stopping once 100 ms have
/// passed so many patterns together can't block the caller.
///
/// Patterns not reached in time are [`UriMatchStatus::Skipped`]. Pass just those to another call
/// to evaluate them: every call evaluates at least one pattern, so repeating this always finishes.
///
/// Nothing is cached between calls, since compiled patterns can be large and hold vault data.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn uri_regex_matches_batch(patterns: Vec<String>, target: &str) -> UriMatchResults {
    UriMatchResults(matches_batch_within(&patterns, target, BATCH_TIME_BUDGET))
}

fn matches_batch_within(
    patterns: &[String],
    target: &str,
    budget: TimeDelta,
) -> Vec<UriMatchStatus> {
    if target.len() > MAX_TARGET_LENGTH {
        return vec![UriMatchStatus::NoMatch; patterns.len()];
    }
    let deadline = Utc::now() + budget;
    let mut results = vec![UriMatchStatus::Skipped; patterns.len()];
    for (i, pattern) in patterns.iter().enumerate() {
        if i > 0 && Utc::now() >= deadline {
            break;
        }
        results[i] = if uri_regex_matches(pattern, target) {
            UriMatchStatus::Match
        } else {
            UriMatchStatus::NoMatch
        };
    }
    results
}

/// Checks that `pattern` is short enough, uses only supported constructs, and compiles, for
/// save-time errors.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub fn validate_uri_regex(pattern: &str) -> Result<(), UriMatcherError> {
    compile(pattern).map(|_| ())
}

/// A compiled pattern.
enum Matcher {
    Plain(Regex),
    /// `^literal(?!excluded)rest`, as `^literal(?:rest)` and not `^literal(?:excluded)`. The
    /// literal matches one way at most, so the lookahead is always checked at the same position.
    ExceptAfterPrefix {
        included: Regex,
        excluded: Regex,
    },
}

impl Matcher {
    fn is_match(&self, target: &str) -> bool {
        match self {
            Self::Plain(regex) => regex.is_match(target),
            Self::ExceptAfterPrefix { included, excluded } => {
                included.is_match(target) && !excluded.is_match(target)
            }
        }
    }
}

fn compile(pattern: &str) -> Result<Matcher, UriMatcherError> {
    if pattern.chars().count() > MAX_PATTERN_LENGTH {
        return Err(UriMatcherError::PatternTooLong);
    }
    match build(pattern) {
        Err(UriMatcherError::UnsupportedConstruct) => {
            let (prefix, excluded, rest) =
                split_prefix_lookahead(pattern).ok_or(UriMatcherError::UnsupportedConstruct)?;
            Ok(Matcher::ExceptAfterPrefix {
                included: build(&format!("^{prefix}(?:{rest})"))?,
                excluded: build(&format!("^{prefix}(?:{excluded})"))?,
            })
        }
        result => result.map(Matcher::Plain),
    }
}

fn build(pattern: &str) -> Result<Regex, UriMatcherError> {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(SIZE_LIMIT)
        .dfa_size_limit(DFA_SIZE_LIMIT)
        .build()
        .map_err(|error| match error {
            regex::Error::CompiledTooBig(_) => UriMatcherError::PatternTooComplex,
            // `regex` only describes syntax errors in text, so parse again for the kind.
            _ => match parse(pattern) {
                Err(
                    ast::ErrorKind::UnsupportedLookAround
                    | ast::ErrorKind::UnsupportedBackreference,
                ) => UriMatcherError::UnsupportedConstruct,
                Err(ast::ErrorKind::NestLimitExceeded(_)) => UriMatcherError::PatternTooComplex,
                _ => UriMatcherError::InvalidPattern,
            },
        })
}

fn parse(pattern: &str) -> Result<Ast, ast::ErrorKind> {
    ast::parse::Parser::new()
        .parse(pattern)
        .map_err(|error| error.kind().clone())
}

/// Splits `^literal(?!excluded)rest` into its three parts, if `pattern` has that form and `rest`
/// has no top-level alternation, which would otherwise bind looser than the prefix.
fn split_prefix_lookahead(pattern: &str) -> Option<(&str, &str, &str)> {
    let (prefix, after) = pattern.strip_prefix('^')?.split_once("(?!")?;
    if !parse(prefix).is_ok_and(|ast| is_literal(&ast)) {
        return None;
    }
    // The first `)` that leaves a valid expression closes the lookahead: one inside a group,
    // class, or escape leaves it unbalanced.
    let (excluded, rest) = after
        .match_indices(')')
        .filter_map(|(i, _)| {
            let (excluded, rest) = after.split_at_checked(i)?;
            Some((excluded, rest.strip_prefix(')')?))
        })
        .find(|(excluded, _)| parse(excluded).is_ok())?;
    match parse(rest) {
        Ok(Ast::Alternation(_)) | Err(_) => None,
        Ok(_) => Some((prefix, excluded, rest)),
    }
}

/// Whether `ast` is plain text, with no flags, classes, groups, or repetition.
fn is_literal(ast: &Ast) -> bool {
    match ast {
        Ast::Empty(_) | Ast::Literal(_) => true,
        Ast::Concat(concat) => concat.asts.iter().all(|ast| matches!(ast, Ast::Literal(_))),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    const BUDGET: Duration = Duration::from_millis(250);

    fn assert_within_budget<T>(f: impl FnOnce() -> T) -> T {
        let start = Instant::now();
        let result = f();
        let elapsed = start.elapsed();
        // Coverage builds are instrumented and too slow for wall-clock limits to mean anything.
        assert!(cfg!(coverage) || elapsed < BUDGET, "took {elapsed:?}");
        result
    }

    fn random_ab(len: usize) -> String {
        let mut seed: u32 = 1;
        (0..len)
            .map(|_| {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                if (seed >> 16) & 1 == 0 { 'a' } else { 'b' }
            })
            .collect()
    }

    #[test]
    fn catastrophic_pattern_finishes_within_budget() {
        for n in [100, 2_000, MAX_TARGET_LENGTH - 1] {
            let target = "a".repeat(n) + "!";
            assert!(!assert_within_budget(|| uri_regex_matches(
                r"^(.+)+#$",
                &target
            )));
        }
    }

    #[test]
    fn worst_patterns_on_longest_target_finish_within_budget() {
        let patterns = [
            r"(?:\w|\W){20}a(?:\w|\W){20}#",
            r"^a(?!(?:\w|\W){20}a(?:\w|\W){20}#)(?:\w|\W){20}a(?:\w|\W){20}#",
        ];
        let target = random_ab(MAX_TARGET_LENGTH);
        for pattern in patterns {
            validate_uri_regex(pattern).expect("pattern should be allowed");
            assert!(!assert_within_budget(|| uri_regex_matches(
                pattern, &target
            )));
        }
    }

    #[test]
    fn lookahead_after_literal_prefix_works() {
        let pattern = r"^https://(?!admin\.)[^/]+\.example\.com/";
        assert!(uri_regex_matches(pattern, "https://www.example.com/login"));
        assert!(!uri_regex_matches(
            pattern,
            "https://admin.example.com/login"
        ));
        assert!(!uri_regex_matches(pattern, "http://www.example.com/login"));

        let pattern = r"^https://example\.com/(?!logout)";
        assert!(uri_regex_matches(pattern, "https://example.com/login"));
        assert!(!uri_regex_matches(pattern, "https://example.com/logout"));

        let pattern = r"^(?!https://admin\.).*\.example\.com/";
        assert!(uri_regex_matches(pattern, "https://www.example.com/"));
        assert!(!uri_regex_matches(pattern, "https://admin.example.com/"));
    }

    #[test]
    fn lookahead_body_can_hold_groups_classes_and_escapes() {
        let pattern = r"^https://(?!(?:admin|root)[.)]|a\)|[)]x)\w+\.example\.com/";
        validate_uri_regex(pattern).expect("pattern should be allowed");
        assert!(uri_regex_matches(pattern, "https://www.example.com/"));
        assert!(!uri_regex_matches(pattern, "https://admin.example.com/"));
        assert!(!uri_regex_matches(pattern, "https://root.example.com/"));
    }

    #[test]
    fn word_boundaries_work() {
        let pattern = r"\bexample\.com\b";
        assert!(uri_regex_matches(pattern, "https://example.com/"));
        assert!(!uri_regex_matches(pattern, "https://myexample.com/"));
    }

    #[test]
    fn matches_case_insensitively_like_javascript_i_flag() {
        let cases = [
            (r"^https://EXAMPLE\.com/", "https://example.com/", true),
            (
                r"^https://example\.com/Login",
                "HTTPS://EXAMPLE.COM/login",
                true,
            ),
            (
                r"^https://[A-Z]+\.example\.com",
                "https://www.example.com",
                true,
            ),
            (
                r"^https://example\.com/(?!Admin)",
                "https://example.com/admin",
                false,
            ),
            (
                r"^HTTPS://example\.com/(?!Admin)",
                "https://example.com/login",
                true,
            ),
            (r"^https:\/\/example\.com\/", "https://example.com/", true),
            (
                r"^https://example\.com/$",
                "https://example.com/path",
                false,
            ),
            (r"\d{4}", "https://example.com/2024", true),
        ];
        for (pattern, target, expected) in cases {
            assert_eq!(uri_regex_matches(pattern, target), expected, "{pattern}");
        }
    }

    #[test]
    fn rejects_invalid_patterns() {
        for pattern in ["(", "[z-a]", r"a{2,1}", r"\", "(?>a|ab)c", r"\K"] {
            assert!(
                matches!(
                    validate_uri_regex(pattern),
                    Err(UriMatcherError::InvalidPattern)
                ),
                "{pattern}"
            );
            assert!(!uri_regex_matches(pattern, "anything"));
        }
    }

    #[test]
    fn rejects_oversized_patterns() {
        assert!(validate_uri_regex(&"a".repeat(MAX_PATTERN_LENGTH)).is_ok());
        assert!(validate_uri_regex(&"é".repeat(MAX_PATTERN_LENGTH)).is_ok());

        let oversized = "a".repeat(MAX_PATTERN_LENGTH + 1);
        assert!(matches!(
            validate_uri_regex(&oversized),
            Err(UriMatcherError::PatternTooLong)
        ));
        assert!(!uri_regex_matches(&oversized, &oversized));
    }

    #[test]
    fn rejects_patterns_that_compile_too_large_or_nest_too_deeply() {
        let too_deep = "(".repeat(300) + &")".repeat(300);
        for pattern in [r"\w{1000}", r"^a(?!\w{1000})", &too_deep] {
            assert!(
                matches!(
                    validate_uri_regex(pattern),
                    Err(UriMatcherError::PatternTooComplex)
                ),
                "{pattern}"
            );
        }
    }

    #[test]
    fn rejects_other_lookarounds_and_backreferences() {
        let patterns = [
            r"(?<=\.)example\.com/",
            r"(?<!admin)\.example\.com/",
            r"^https://(\w+)\.example\.com/\1/",
            r"^a(?=b)",
            r"x(?!.*logout)",
            r"^a*(?!logout)",
            r"^https://[^/]+(?!admin)",
            r"^(?i)a(?!b)",
            r"^a(?!b)c(?!d)",
            r"^a(?!(?!b))",
            r"^a(?!b)c|d",
            r"^a(?!b)\1",
            r"(?:^a(?!b))",
        ];
        for pattern in patterns {
            assert!(
                matches!(
                    validate_uri_regex(pattern),
                    Err(UriMatcherError::UnsupportedConstruct)
                ),
                "{pattern}"
            );
            assert!(!uri_regex_matches(pattern, "aaaa"));
        }
    }

    #[test]
    fn allows_alternation_inside_the_lookahead_and_rest() {
        let pattern = r"^https://(?!admin\.|root\.)(?:www|shop)\.example\.com/";
        assert!(uri_regex_matches(pattern, "https://shop.example.com/"));
        assert!(!uri_regex_matches(pattern, "https://root.example.com/"));
    }

    #[test]
    fn oversized_target_never_matches() {
        for pattern in ["a", "^a(?!b)"] {
            assert!(uri_regex_matches(pattern, &"a".repeat(MAX_TARGET_LENGTH)));
            assert!(
                matches!(
                    try_uri_regex_match(pattern, &"a".repeat(MAX_TARGET_LENGTH + 1)),
                    Err(UriMatcherError::TargetTooLong)
                ),
                "{pattern}"
            );
        }
    }

    fn batch<S: AsRef<str>>(patterns: &[S], target: &str) -> Vec<UriMatchStatus> {
        let patterns = patterns.iter().map(|p| p.as_ref().to_owned()).collect();
        uri_regex_matches_batch(patterns, target).0
    }

    #[test]
    fn batch_returns_results_in_order() {
        let patterns = [
            r"example\.com",
            "(",
            r"^https://other\.com",
            r"^https://(?!admin\.)",
        ];
        assert_eq!(
            batch(&patterns, "https://www.example.com/"),
            [
                UriMatchStatus::Match,
                UriMatchStatus::NoMatch,
                UriMatchStatus::NoMatch,
                UriMatchStatus::Match,
            ]
        );
    }

    #[test]
    fn batch_keeps_results_reached_before_the_budget_runs_out() {
        // Every pattern matches, and compiling all the long ones would exceed the budget.
        let filler = "(?:x|y)".repeat(140);
        let mut patterns = vec!["^a".to_owned()];
        patterns.extend((0..20_000).map(|i| format!("^a|{filler}{i}")));

        let results = assert_within_budget(|| batch(&patterns, "abc"));

        assert_eq!(results[0], UriMatchStatus::Match);
        assert!(results.contains(&UriMatchStatus::Skipped));
        assert!(!results.contains(&UriMatchStatus::NoMatch));
    }

    #[test]
    fn resubmitting_skipped_patterns_evaluates_every_pattern() {
        let patterns: Vec<String> = [
            r"^https://(?!admin\.)",
            "(",
            r"^https://www\.",
            r"(\w+)\.\1",
            r"^https://other\.com",
            r"\bwww\b",
        ]
        .map(str::to_owned)
        .into();
        let target = "https://www.example.com/";
        let expected: Vec<_> = patterns
            .iter()
            .map(|pattern| {
                if uri_regex_matches(pattern, target) {
                    UriMatchStatus::Match
                } else {
                    UriMatchStatus::NoMatch
                }
            })
            .collect();

        // With no budget each call evaluates as little as allowed, so this checks the minimum.
        let mut results = vec![UriMatchStatus::Skipped; patterns.len()];
        let mut pending: Vec<usize> = (0..patterns.len()).collect();
        while !pending.is_empty() {
            let batch: Vec<String> = pending.iter().map(|&i| patterns[i].clone()).collect();
            let statuses = matches_batch_within(&batch, target, TimeDelta::zero());
            let mut still_pending = Vec::new();
            for (&i, status) in pending.iter().zip(statuses) {
                results[i] = status;
                if status == UriMatchStatus::Skipped {
                    still_pending.push(i);
                }
            }
            assert!(
                still_pending.len() < pending.len(),
                "a call evaluated nothing"
            );
            pending = still_pending;
        }

        assert_eq!(results, expected);
    }

    #[test]
    fn batch_rejects_oversized_target_without_evaluating() {
        let target = "a".repeat(MAX_TARGET_LENGTH + 1);
        let results = assert_within_budget(|| batch(&["a", "^a"], &target));
        assert_eq!(results, [UriMatchStatus::NoMatch, UriMatchStatus::NoMatch]);
    }

    #[test]
    fn error_messages_do_not_contain_the_pattern() {
        let pattern = "(secret-pattern";
        let message = validate_uri_regex(pattern)
            .expect_err("invalid pattern")
            .to_string();
        assert!(!message.contains("secret"));
    }
}
