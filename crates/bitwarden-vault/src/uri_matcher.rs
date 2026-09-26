//! Regular-expression URI matching with bounded pattern size and execution time, using
//! [`fancy_regex`] plus the shape restrictions in [`check_shape`].

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, LazyLock, Mutex, PoisonError},
};

use bitwarden_error::bitwarden_error;
use chrono::{TimeDelta, Utc};
use fancy_regex::{
    Assertion, CompileError, Error as RegexError, Expr, ParseError, Regex, RegexBuilder,
};
use thiserror::Error;

/// Maximum accepted pattern length, in characters.
pub const MAX_PATTERN_LENGTH: usize = 1_000;

/// Maximum target length, in bytes, that patterns are evaluated against.
pub const MAX_TARGET_LENGTH: usize = 4_096;
/// Maximum number of lookarounds plus backreferences, each of which may rescan the target.
pub const MAX_EXPENSIVE_NODES: usize = 8;

/// Longest lookaround body, in characters.
const MAX_LOOKAROUND_WIDTH: usize = 32;
/// Backtracking steps allowed per match before it is abandoned as no match.
const BACKTRACK_LIMIT: usize = 10_000;
/// Approximate compiled size limit for each part delegated to the `regex` crate.
const DELEGATE_SIZE_LIMIT: usize = 1 << 20;
/// Approximate lazy DFA cache size for each part delegated to the `regex` crate.
const DELEGATE_DFA_SIZE_LIMIT: usize = 1 << 20;
/// Time after which [`uri_regex_matches_batch`] stops evaluating further patterns.
const BATCH_TIME_BUDGET: TimeDelta = TimeDelta::milliseconds(100);
/// Number of compiled patterns kept in memory.
const CACHE_CAPACITY: usize = 128;

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
    /// The pattern compiles too large, or has more than [`MAX_EXPENSIVE_NODES`] lookarounds and
    /// backreferences.
    #[error("Pattern is too complex")]
    PatternTooComplex,
    /// The pattern uses a construct whose cost cannot be bounded, such as a long, nested, or
    /// repeated lookaround, a word boundary, or an atomic group.
    #[error("Pattern uses an unsupported construct")]
    UnsupportedConstruct,
    /// The target is longer than [`MAX_TARGET_LENGTH`].
    #[error("Target exceeds the maximum length")]
    TargetTooLong,
    /// Evaluating the pattern exceeded the backtracking limit.
    #[error("Pattern exceeded the matching limit")]
    MatchLimitExceeded,
}

/// Returns whether `target` matches `pattern`, case-insensitively. Invalid, oversized, and
/// too-expensive patterns never match.
pub fn uri_regex_matches(pattern: &str, target: &str) -> bool {
    try_uri_regex_match(pattern, target).unwrap_or(false)
}

/// Evaluates each pattern against `target`, one result per pattern. Patterns reached after 100 ms
/// never match, so many expensive patterns together can't block the caller either.
pub fn uri_regex_matches_batch<S: AsRef<str>>(patterns: &[S], target: &str) -> Vec<bool> {
    let deadline = Utc::now() + BATCH_TIME_BUDGET;
    let mut results = vec![false; patterns.len()];
    // Linear patterns go first so expensive ones can't use up the budget meant for them.
    let (linear, backtracking): (Vec<usize>, Vec<usize>) =
        (0..patterns.len()).partition(|&i| pattern_is_linear(patterns[i].as_ref()));
    for i in linear.into_iter().chain(backtracking) {
        if Utc::now() >= deadline {
            break;
        }
        results[i] = uri_regex_matches(patterns[i].as_ref(), target);
    }
    results
}

/// Like [`uri_regex_matches`], but reports why a pattern could not be evaluated.
pub fn try_uri_regex_match(pattern: &str, target: &str) -> Result<bool, UriMatcherError> {
    if target.len() > MAX_TARGET_LENGTH {
        return Err(UriMatcherError::TargetTooLong);
    }
    let regex = cached_compile(pattern)?;
    regex.is_match(target).map_err(map_regex_error)
}

/// Checks that `pattern` is short enough, has a supported shape, and compiles, for save-time
/// errors.
pub fn validate_uri_regex(pattern: &str) -> Result<(), UriMatcherError> {
    // Bypasses the cache so validating each keystroke does not evict patterns in use.
    compile(pattern).map(|_| ())
}

fn compile(pattern: &str) -> Result<Regex, UriMatcherError> {
    if pattern.chars().count() > MAX_PATTERN_LENGTH {
        return Err(UriMatcherError::PatternTooLong);
    }
    let tree = Expr::parse_tree(pattern).map_err(map_regex_error)?;
    if check_shape(&tree.expr)? > MAX_EXPENSIVE_NODES {
        return Err(UriMatcherError::PatternTooComplex);
    }

    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .backtrack_limit(BACKTRACK_LIMIT)
        .delegate_size_limit(DELEGATE_SIZE_LIMIT)
        .delegate_dfa_size_limit(DELEGATE_DFA_SIZE_LIMIT)
        .build()
        .map_err(map_regex_error)
}

/// Anchors the `regex` crate handles itself; word boundaries force fancy-regex's backtracking.
fn is_linear_assertion(assertion: &Assertion) -> bool {
    matches!(
        assertion,
        Assertion::StartText
            | Assertion::EndText
            | Assertion::StartLine { .. }
            | Assertion::EndLine { .. }
    )
}

fn pattern_is_linear(pattern: &str) -> bool {
    pattern.chars().count() <= MAX_PATTERN_LENGTH
        && Expr::parse_tree(pattern).is_ok_and(|tree| is_linear(&tree.expr))
}

/// Whether fancy-regex hands all of `expr` to the linear-time `regex` crate. Mirrors fancy-regex's
/// analysis: lookarounds, backreferences, word boundaries, and `\R` need its backtracking engine.
fn is_linear(expr: &Expr) -> bool {
    match expr {
        Expr::Empty | Expr::Any { .. } | Expr::Literal { .. } | Expr::Delegate { .. } => true,
        Expr::Assertion(assertion) => is_linear_assertion(assertion),
        Expr::Concat(exprs) | Expr::Alt(exprs) => exprs.iter().all(is_linear),
        Expr::Group(child) => is_linear(child),
        Expr::Repeat { child, .. } => is_linear(child),
        _ => false,
    }
}

fn map_regex_error(error: RegexError) -> UriMatcherError {
    match error {
        RegexError::ParseError(_, ParseError::RecursionExceeded) => {
            UriMatcherError::PatternTooComplex
        }
        RegexError::CompileError(compile_error) => match *compile_error {
            CompileError::InnerError(inner) if inner.size_limit().is_some() => {
                UriMatcherError::PatternTooComplex
            }
            _ => UriMatcherError::InvalidPattern,
        },
        RegexError::RuntimeError(_) => UriMatcherError::MatchLimitExceeded,
        _ => UriMatcherError::InvalidPattern,
    }
}

/// Where a node sits in the pattern.
#[derive(Clone, Copy, Default)]
struct Context {
    in_repetition: bool,
    in_lookaround: bool,
}

const IN_LOOKAROUND: Context = Context {
    in_repetition: false,
    in_lookaround: true,
};

/// Rejects shapes where fancy-regex does work its backtrack limit doesn't count, and returns the
/// number of lookarounds and backreferences.
fn check_shape(expr: &Expr) -> Result<usize, UriMatcherError> {
    check_node(expr, Context::default())
}

fn check_node(expr: &Expr, context: Context) -> Result<usize, UriMatcherError> {
    match expr {
        Expr::Empty | Expr::Any { .. } | Expr::Literal { .. } | Expr::Delegate { .. } => Ok(0),
        Expr::Assertion(assertion) if is_linear_assertion(assertion) => Ok(0),
        Expr::Backref { .. } if !context.in_lookaround => Ok(1),
        Expr::Concat(exprs) | Expr::Alt(exprs) => exprs
            .iter()
            .try_fold(0, |total, child| Ok(total + check_node(child, context)?)),
        Expr::Group(child) => check_node(child, context),
        Expr::Repeat { child, hi, .. } => check_node(
            child,
            Context {
                in_repetition: context.in_repetition || *hi > 1,
                ..context
            },
        ),
        Expr::LookAround(child, _)
            if !context.in_repetition
                && !context.in_lookaround
                && max_width(child).is_some_and(|width| width <= MAX_LOOKAROUND_WIDTH) =>
        {
            Ok(check_node(child, IN_LOOKAROUND)? + 1)
        }
        _ => Err(UriMatcherError::UnsupportedConstruct),
    }
}

/// Longest text `expr` can match, in characters, or `None` if unbounded or unknown.
fn max_width(expr: &Expr) -> Option<usize> {
    match expr {
        Expr::Empty | Expr::Assertion(_) => Some(0),
        Expr::Any { .. } | Expr::Delegate { .. } => Some(1),
        Expr::GeneralNewline { .. } => Some(2),
        Expr::Literal { val, .. } => Some(val.chars().count()),
        Expr::Concat(exprs) => exprs
            .iter()
            .try_fold(0usize, |total, child| total.checked_add(max_width(child)?)),
        Expr::Alt(exprs) => exprs
            .iter()
            .try_fold(0usize, |widest, child| Some(widest.max(max_width(child)?))),
        Expr::Group(child) => max_width(child),
        Expr::Repeat { child, hi, .. } if *hi != usize::MAX => max_width(child)?.checked_mul(*hi),
        _ => None,
    }
}

type CacheEntry = Result<Arc<Regex>, UriMatcherError>;

/// Bounded first-in, first-out cache of compiled patterns, including ones that failed to compile.
#[derive(Default)]
struct PatternCache {
    entries: HashMap<Arc<str>, CacheEntry>,
    order: VecDeque<Arc<str>>,
}

impl PatternCache {
    fn get_or_compile(&mut self, pattern: &str) -> CacheEntry {
        if let Some(compiled) = self.entries.get(pattern) {
            return compiled.clone();
        }

        let compiled = compile(pattern).map(Arc::new);
        if self.order.len() >= CACHE_CAPACITY
            && let Some(oldest) = self.order.pop_front()
        {
            self.entries.remove(&oldest);
        }
        let key: Arc<str> = Arc::from(pattern);
        self.order.push_back(key.clone());
        self.entries.insert(key, compiled.clone());
        compiled
    }
}

static PATTERN_CACHE: LazyLock<Mutex<PatternCache>> = LazyLock::new(Default::default);

fn cached_compile(pattern: &str) -> CacheEntry {
    // Checked before the cache so oversized patterns are never stored.
    if pattern.chars().count() > MAX_PATTERN_LENGTH {
        return Err(UriMatcherError::PatternTooLong);
    }

    PATTERN_CACHE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get_or_compile(pattern)
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
        assert!(elapsed < BUDGET, "took {elapsed:?}");
        result
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
    fn backtrack_limit_returns_no_match_instead_of_hanging() {
        let target = "a".repeat(2_000) + "!";
        let result = assert_within_budget(|| try_uri_regex_match(r"^(.+)+\1#$", &target));
        assert!(matches!(result, Err(UriMatcherError::MatchLimitExceeded)));
        assert!(!uri_regex_matches(r"^(.+)+\1#$", &target));
    }

    #[test]
    fn worst_allowed_shapes_finish_within_budget() {
        let patterns = [
            "(?=[\\w/.:-]{0,31}\\w)".repeat(8) + "#",
            "(.*)(.*)".to_owned() + &"(?<=[ab]{31}[ab])".repeat(6) + r"\1\2#",
            r"(.*)\1\1\1\1\1\1\1#".to_owned(),
        ];
        let mut seed: u32 = 1;
        let target: String = (0..MAX_TARGET_LENGTH)
            .map(|_| {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                if (seed >> 16) & 1 == 0 { 'a' } else { 'b' }
            })
            .collect();
        for pattern in &patterns {
            validate_uri_regex(pattern).expect("pattern should be allowed");
            assert!(!assert_within_budget(|| uri_regex_matches(
                pattern, &target
            )));
        }
    }

    #[test]
    fn lookahead_works() {
        let pattern = r"^https://(?!admin\.)[^/]+\.example\.com/";
        assert!(uri_regex_matches(pattern, "https://www.example.com/login"));
        assert!(!uri_regex_matches(
            pattern,
            "https://admin.example.com/login"
        ));

        let pattern = r"^https://example\.com/(?!logout)";
        assert!(uri_regex_matches(pattern, "https://example.com/login"));
        assert!(!uri_regex_matches(pattern, "https://example.com/logout"));
    }

    #[test]
    fn lookbehind_works() {
        let pattern = r"(?<=\.)example\.com/";
        assert!(uri_regex_matches(pattern, "https://www.example.com/"));
        assert!(!uri_regex_matches(pattern, "https://example.com/"));

        let pattern = r"(?<!admin)\.example\.com/";
        assert!(uri_regex_matches(pattern, "https://www.example.com/"));
        assert!(!uri_regex_matches(pattern, "https://admin.example.com/"));
    }

    #[test]
    fn backreference_works() {
        let pattern = r"^https://(\w+)\.example\.com/\1/";
        assert!(uri_regex_matches(pattern, "https://shop.example.com/shop/"));
        assert!(!uri_regex_matches(
            pattern,
            "https://shop.example.com/blog/"
        ));
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
                r"example\.com/(?!Admin)",
                "https://example.com/admin",
                false,
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
        for pattern in ["(", "[z-a]", r"a{2,1}", r"\"] {
            assert!(matches!(
                validate_uri_regex(pattern),
                Err(UriMatcherError::InvalidPattern)
            ));
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
    fn rejects_patterns_that_compile_too_large() {
        assert!(matches!(
            validate_uri_regex(r"\w{1000}"),
            Err(UriMatcherError::PatternTooComplex)
        ));
    }

    #[test]
    fn rejects_too_many_lookarounds_and_backreferences() {
        let allowed = "(?=a)".repeat(MAX_EXPENSIVE_NODES);
        assert!(validate_uri_regex(&allowed).is_ok());
        let too_many = "(?=a)".repeat(MAX_EXPENSIVE_NODES + 1);
        assert!(matches!(
            validate_uri_regex(&too_many),
            Err(UriMatcherError::PatternTooComplex)
        ));
    }

    #[test]
    fn rejects_unbounded_shapes() {
        let patterns = [
            r"^(?:(?=(?:(?=[^#]*$).)*$).)*#",
            r"^(?:(?=[^#]*$).)*#",
            r"(?:(?=a)b)+",
            r"x(?!.*logout)",
            r"\bexample\b",
            r"\Bx",
            r"a\R",
            r"^(?!.*logout).*example\.com",
            r"(?m)^(?!.*logout)",
            r"^a*(?!.*logout)",
            r"(?=(.*))\1",
            r"(a)(?=\1)",
            r"a++",
            r"(?>a|ab)c",
            r"(?(1)a|b)",
            r"\Ka",
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
    fn allows_only_short_lookarounds() {
        let long = format!("(?={})", "a".repeat(MAX_LOOKAROUND_WIDTH));
        assert!(validate_uri_regex(&format!("x{long}")).is_ok());
        let too_long = format!("(?={})", "a".repeat(MAX_LOOKAROUND_WIDTH + 1));
        assert!(validate_uri_regex(&format!("x{too_long}")).is_err());
        assert!(validate_uri_regex(&format!("^{too_long}")).is_err());
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
    fn oversized_target_never_matches() {
        for pattern in ["a", r"(?<=a)a", r"(a)\1"] {
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

    #[test]
    fn classifies_patterns_the_regex_crate_runs_alone_as_linear() {
        let linear = [
            r"^https://[^/]+\.example\.com/.*$",
            r"(?m)^a$",
            r"^(.+)+#$",
            r"(a|b)*c{2,5}",
        ];
        for pattern in linear {
            assert!(pattern_is_linear(pattern), "{pattern}");
        }

        let backtracking = [r"\bexample", r"\Bx", r"a\R", r"(a)\1", r"(?=a)", r"(?<!a)b"];
        for pattern in backtracking {
            assert!(!pattern_is_linear(pattern), "{pattern}");
        }
        assert!(!pattern_is_linear("("));
    }

    #[test]
    fn worst_linear_pattern_on_longest_target_finishes_within_budget() {
        let pattern = r"(?:\w|\W){20}a(?:\w|\W){20}#";
        let target = random_ab(MAX_TARGET_LENGTH);
        assert!(!assert_within_budget(|| uri_regex_matches(
            pattern, &target
        )));
    }

    #[test]
    fn batch_evaluates_linear_patterns_before_expensive_ones() {
        let expensive = "(?=[\\w/.:-]{0,31}\\w)".repeat(8);
        let mut patterns: Vec<String> = (0..60).map(|i| format!("{expensive}#{i}")).collect();
        patterns.push("^a".to_owned());
        let target = "a".to_owned() + &random_ab(MAX_TARGET_LENGTH - 1);

        let results = assert_within_budget(|| uri_regex_matches_batch(&patterns, &target));

        assert_eq!(results.last(), Some(&true));
    }

    #[test]
    fn batch_returns_results_in_order() {
        let patterns = [
            r"example\.com",
            "(",
            r"^https://other\.com",
            r"(?<=\.)example",
        ];
        assert_eq!(
            uri_regex_matches_batch(&patterns, "https://www.example.com/"),
            vec![true, false, false, true]
        );
    }

    #[test]
    fn cache_is_bounded_and_keeps_answers_correct() {
        let mut cache = PatternCache::default();
        for i in 0..CACHE_CAPACITY + 10 {
            let pattern = format!("^{i}$");
            let regex = cache.get_or_compile(&pattern).expect("valid pattern");
            assert!(regex.is_match(&i.to_string()).expect("no runtime error"));
        }
        assert_eq!(cache.entries.len(), CACHE_CAPACITY);
        assert_eq!(cache.order.len(), CACHE_CAPACITY);
        assert!(cache.get_or_compile("(").is_err());
        assert!(cache.get_or_compile("(").is_err());
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
