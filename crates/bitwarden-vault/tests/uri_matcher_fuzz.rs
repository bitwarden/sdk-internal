//! Randomized check that every pattern `validate_uri_regex` accepts is evaluated within the time
//! budget on adversarial targets. The ignored test runs longer; see `long_fuzz`.

use std::{
    env,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use bitwarden_vault::{MAX_TARGET_LENGTH, try_uri_regex_match, validate_uri_regex};

/// Native per-evaluation limit, leaving headroom under the 250 ms budget in slower WASM builds.
const EVALUATION_LIMIT: Duration = Duration::from_millis(100);

const ATOMS: &[&str] = &[
    "a",
    "b",
    "ab",
    ".",
    "[ab]",
    "[^#]",
    r"\w",
    r"\W",
    r"[\w/.:-]",
    r"\d",
    "#",
    "/",
    r"\.",
    "(?:a|b)",
];
/// Unbounded runs that make a lookaround scan to the end of the target.
const SCANNERS: &[&str] = &[".*", "[^#]*", r"[\w/.:-]*", "[ab]*", r"\w*"];
const ASSERTIONS: &[&str] = &[r"\b", r"\B", "$", "^", r"\R"];
const QUANTIFIERS: &[&str] = &["*", "+", "?", "*?", "+?", "{0,3}", "{2}", "{2,}", "{1,30}"];
const LOOKAROUNDS: &[&str] = &["(?=", "(?!", "(?<=", "(?<!"];
/// Constructs `validate_uri_regex` must always reject.
const REJECTED: &[&str] = &["(?>a|ab)", "a++", r"\K", "(?(1)a|b)", r"\G", "(?1)"];

/// Patterns found by fuzzing earlier versions of the rules; each must be rejected or fast.
const REGRESSIONS: &[&str] = &[
    r"^(?=[^#]*\B)(?=[^#]*[ab])(?![\w/.:-]*a[\w/.:-]{15}$)(?=[\w/.:-]*\.)(.+?)\1[^#]$/\R",
    r"^(?=[ab]*\B)(?=([ab]?))(?!.*\W)(?!.*a[\w/.:-]{19}$)(?=\w*^)(?=[^#]*\d)#",
    r"^(?=[^#]*\B)(?=[\w/.:-]*a[ab]{18}\w).*\w(?:\W){2,}",
    r"^(?=[ab]*\B)(?=.*a[\w/.:-]{13}b)(?!([^#]*))(?=[^#]*[\w/.:-])\R[^#]+\b",
    r"(?:(?![^#]*a\w{28}\w)\.){1,30}(?!/)\w*[^#]*a",
    r"^(?:(?=(?:(?=[^#]*$).)*$).)*#",
    r"\b(?:/|[ab] )*\d{2}(?:a|b)($)",
    r"(?:[^#]{1,30}){1,30}[ab]*/",
    r"(.)\b((?:[^#]*)+)(?:(?:\w(?:a|b)){1,30}){2}b*?(?:\.){0,3}(\d)",
];

/// Small deterministic xorshift generator, so failures reproduce from the seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
}

/// Generates a random expression, weighted toward constructs that are expensive to backtrack.
fn expr(rng: &mut Rng, depth: usize, groups: &mut usize) -> String {
    if depth == 0 {
        return rng.pick(ATOMS).to_owned();
    }
    match rng.below(17) {
        0 | 1 => rng.pick(ATOMS).to_owned(),
        2 => rng.pick(SCANNERS).to_owned(),
        3 => rng.pick(ASSERTIONS).to_owned(),
        4 => (0..2 + rng.below(3))
            .map(|_| expr(rng, depth - 1, groups))
            .collect(),
        5 => (0..2 + rng.below(2))
            .map(|_| expr(rng, depth - 1, groups))
            .collect::<Vec<_>>()
            .join("|"),
        6 => {
            *groups += 1;
            format!("({})", expr(rng, depth - 1, groups))
        }
        7 => format!(
            "(?:{}){}",
            expr(rng, depth - 1, groups),
            rng.pick(QUANTIFIERS)
        ),
        8 => format!("{}{}", rng.pick(ATOMS), rng.pick(QUANTIFIERS)),
        9 | 10 => lookaround(rng, depth, groups),
        // A lookaround retried on every iteration of a loop.
        11 => format!(
            "(?:{}{}){}",
            lookaround(rng, depth, groups),
            rng.pick(ATOMS),
            rng.pick(QUANTIFIERS)
        ),
        // Several lookarounds retried at every start position.
        12 => (0..2 + rng.below(7))
            .map(|_| lookaround(rng, depth, groups))
            .collect(),
        13 if *groups > 0 => format!(r"\{}", 1 + rng.below(*groups)),
        14 if rng.chance(50) => rng.pick(REJECTED).to_owned(),
        // A word boundary before a loop that can match at every start position.
        15 => format!(r"\b(?:{}|{} )*", rng.pick(ATOMS), rng.pick(ATOMS)),
        _ => rng.pick(ATOMS).to_owned(),
    }
}

/// A lookaround whose body often scans far ahead or thrashes the lazy DFA, or stays just within
/// the width limit so the rules accept it.
fn lookaround(rng: &mut Rng, depth: usize, groups: &mut usize) -> String {
    let class = rng.pick(&["[ab]", r"[\w/.:-]", r"\w", "[^#]", "."]);
    let body = match rng.below(7) {
        0 => format!("{}{}", rng.pick(SCANNERS), rng.pick(ATOMS)),
        1 => format!(
            "{}a{}{{{}}}{}",
            rng.pick(SCANNERS),
            rng.pick(&["[ab]", r"[\w/.:-]", r"\w"]),
            10 + rng.below(20),
            rng.pick(&["$", r"\w", "b"])
        ),
        2 => format!("{}{}", rng.pick(SCANNERS), expr(rng, depth - 1, groups)),
        3 => format!("{class}{{0,{}}}{}", 1 + rng.below(30), rng.pick(ATOMS)),
        4 => format!(
            "a{class}{{{}}}{}",
            10 + rng.below(20),
            rng.pick(&["b", r"\w", "[ab]"])
        ),
        5 => format!(
            "(?:{}|{}){{1,{}}}",
            rng.pick(ATOMS),
            rng.pick(ATOMS),
            1 + rng.below(15)
        ),
        _ => expr(rng, depth - 1, groups),
    };
    format!("{}{body})", rng.pick(LOOKAROUNDS))
}

fn pattern(rng: &mut Rng) -> String {
    let mut groups = 0;
    let body: String = (0..1 + rng.below(4))
        .map(|_| expr(rng, 4, &mut groups))
        .collect();
    if !rng.chance(30) {
        return body;
    }

    // Stacked lookaheads after `^`, which an earlier version of the rules allowed unbounded.
    let prefix: String = (0..rng.below(12))
        .map(|_| lookaround(rng, 3, &mut groups).replacen("(?<", "(?", 1))
        .collect();
    format!("^{prefix}{body}")
}

fn random_text(rng: &mut Rng, alphabet: &[u8], len: usize) -> String {
    (0..len)
        .map(|_| alphabet[rng.below(alphabet.len())] as char)
        .collect()
}

fn targets(rng: &mut Rng) -> Vec<(&'static str, String)> {
    let len = MAX_TARGET_LENGTH;
    vec![
        ("uniform", "a".repeat(len - 1) + "!"),
        ("random-ab", random_text(rng, b"ab", len)),
        ("url-like", random_text(rng, b"ab/.:-#_ ", len)),
        ("pairs", "a ".repeat(len / 2)),
    ]
}

fn uses_backtracking_engine(pattern: &str) -> bool {
    ["(?=", "(?!", "(?<"]
        .iter()
        .any(|token| pattern.contains(token))
        || (1..=9).any(|group| pattern.contains(&format!(r"\{group}")))
}

/// Panics unless `pattern` evaluates within [`EVALUATION_LIMIT`] on every adversarial target.
fn assert_fast(rng: &mut Rng, pattern: &str, context: &str) {
    for (kind, target) in targets(rng) {
        let start = Instant::now();
        let _ = try_uri_regex_match(pattern, &target);
        let elapsed = start.elapsed();
        assert!(
            elapsed < EVALUATION_LIMIT,
            "{context}: {pattern:?} took {elapsed:?} on a {}-byte {kind} target",
            target.len()
        );
    }
}

/// Checks `accepted_target` accepted patterns from `seed`, panicking with a reproducible message.
fn fuzz(seed: u64, accepted_target: usize) {
    let mut rng = Rng(seed.max(1));
    let mut accepted = 0;
    let mut accepted_backtracking = 0;

    for _ in 0..accepted_target * 100 {
        if accepted >= accepted_target {
            break;
        }
        let pattern = pattern(&mut rng);
        let valid = validate_uri_regex(&pattern).is_ok();
        let has_rejected = ["(?>", r"\K", "(?(", r"\G", "(?1)", "++"]
            .iter()
            .any(|token| pattern.contains(token));
        assert!(
            !(valid && has_rejected),
            "seed {seed}: accepted a rejected construct in {pattern:?}"
        );
        if !valid {
            continue;
        }

        accepted += 1;
        if uses_backtracking_engine(&pattern) {
            accepted_backtracking += 1;
        }
        assert_fast(&mut rng, &pattern, &format!("seed {seed}"));
    }

    assert_eq!(
        accepted, accepted_target,
        "seed {seed}: generator found too few valid patterns"
    );
    assert!(
        accepted_backtracking * 4 >= accepted,
        "seed {seed}: only {accepted_backtracking} of {accepted} patterns used the backtracking engine"
    );
}

#[test]
fn regressions_are_rejected_or_fast() {
    let mut rng = Rng(1);
    for pattern in REGRESSIONS {
        assert_fast(&mut rng, pattern, "regression");
    }
}

#[test]
fn accepted_patterns_evaluate_within_budget() {
    fuzz(0x5EED_CAFE, 1_000);
}

/// Longer run: `URI_MATCHER_FUZZ_SEED` and `URI_MATCHER_FUZZ_PATTERNS` override the defaults.
#[test]
#[ignore = "long-running fuzz test"]
fn long_fuzz() {
    let seed = env::var("URI_MATCHER_FUZZ_SEED")
        .ok()
        .and_then(|seed| seed.parse().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(1, |now| now.as_nanos() as u64)
        });
    let patterns = env::var("URI_MATCHER_FUZZ_PATTERNS")
        .ok()
        .and_then(|patterns| patterns.parse().ok())
        .unwrap_or(20_000);
    fuzz(seed, patterns);
}
