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
/// Unbounded runs, which are cheap alone but grow the automaton when nested or counted.
const SCANNERS: &[&str] = &[".*", "[^#]*", r"[\w/.:-]*", "[ab]*", r"\w*"];
const ASSERTIONS: &[&str] = &[r"\b", r"\B", "$", "^"];
const QUANTIFIERS: &[&str] = &["*", "+", "?", "*?", "+?", "{0,3}", "{2}", "{2,}", "{1,30}"];
/// Literal prefixes for the supported `^literal(?!excluded)rest` form.
const PREFIXES: &[&str] = &["", "a", "https://", r"https://www\.", r"ab\.a/"];
/// Constructs `validate_uri_regex` must always reject.
const REJECTED: &[&str] = &[
    "(?>a|ab)",
    r"\K",
    "(?(1)a|b)",
    r"\G",
    "(?1)",
    "(?=a)",
    "(?<=a)",
    "(?<!a)",
    r"(a)\1",
];

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
    r"^(?![^#]*a\w{28}\w)(?:[^#]{1,30}){1,30}[ab]*/",
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

/// Generates a random expression, weighted toward constructs that grow the automaton.
fn expr(rng: &mut Rng, depth: usize) -> String {
    if depth == 0 {
        return rng.pick(ATOMS).to_owned();
    }
    match rng.below(13) {
        0 | 1 => rng.pick(ATOMS).to_owned(),
        2 => rng.pick(SCANNERS).to_owned(),
        3 => rng.pick(ASSERTIONS).to_owned(),
        4 => (0..2 + rng.below(3))
            .map(|_| expr(rng, depth - 1))
            .collect(),
        5 => (0..2 + rng.below(2))
            .map(|_| expr(rng, depth - 1))
            .collect::<Vec<_>>()
            .join("|"),
        6 => format!("({})", expr(rng, depth - 1)),
        7 => format!("(?:{}){}", expr(rng, depth - 1), rng.pick(QUANTIFIERS)),
        8 => format!("{}{}", rng.pick(ATOMS), rng.pick(QUANTIFIERS)),
        // A counted run far from the end, which thrashes the lazy DFA.
        9 => format!(
            "{}a{}{{{}}}{}",
            rng.pick(SCANNERS),
            rng.pick(&["[ab]", r"[\w/.:-]", r"\w", "(?:a|b)"]),
            10 + rng.below(20),
            rng.pick(&["$", r"\w", "b"])
        ),
        10 if rng.chance(50) => rng.pick(REJECTED).to_owned(),
        // A word boundary before a loop that can match at every start position.
        11 => format!(r"\b(?:{}|{} )*", rng.pick(ATOMS), rng.pick(ATOMS)),
        _ => rng.pick(ATOMS).to_owned(),
    }
}

fn pattern(rng: &mut Rng) -> String {
    let body: String = (0..1 + rng.below(4)).map(|_| expr(rng, 4)).collect();
    if rng.chance(50) {
        return body;
    }
    let prefix = rng.pick(PREFIXES);
    let excluded: String = (0..1 + rng.below(3)).map(|_| expr(rng, 3)).collect();
    format!("^{prefix}(?!{excluded}){body}")
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

fn uses_lookahead(pattern: &str) -> bool {
    pattern.contains("(?!")
}

/// Panics unless `pattern` evaluates within [`EVALUATION_LIMIT`] on every adversarial target.
fn assert_fast(rng: &mut Rng, pattern: &str, context: &str) {
    for (kind, target) in targets(rng) {
        let start = Instant::now();
        let _ = try_uri_regex_match(pattern, &target);
        let elapsed = start.elapsed();
        // Coverage builds are instrumented and too slow for wall-clock limits to mean anything.
        assert!(
            cfg!(coverage) || elapsed < EVALUATION_LIMIT,
            "{context}: {pattern:?} took {elapsed:?} on a {}-byte {kind} target",
            target.len()
        );
    }
}

/// Checks `accepted_target` accepted patterns from `seed`, panicking with a reproducible message.
fn fuzz(seed: u64, accepted_target: usize) {
    let mut rng = Rng(seed.max(1));
    let mut accepted = 0;
    let mut accepted_lookahead = 0;

    for _ in 0..accepted_target * 100 {
        if accepted >= accepted_target {
            break;
        }
        let pattern = pattern(&mut rng);
        let valid = validate_uri_regex(&pattern).is_ok();
        let has_rejected = REJECTED.iter().any(|token| pattern.contains(token));
        assert!(
            !(valid && has_rejected),
            "seed {seed}: accepted a rejected construct in {pattern:?}"
        );
        if !valid {
            continue;
        }

        accepted += 1;
        if uses_lookahead(&pattern) {
            accepted_lookahead += 1;
        }
        assert_fast(&mut rng, &pattern, &format!("seed {seed}"));
    }

    assert_eq!(
        accepted, accepted_target,
        "seed {seed}: generator found too few valid patterns"
    );
    assert!(
        accepted_lookahead * 4 >= accepted,
        "seed {seed}: only {accepted_lookahead} of {accepted} patterns used a lookahead"
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
