use serde::Serialize;
#[cfg(feature = "wasm")]
use tsify::Tsify;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{UriMatcher, UriMatcherError, validate_uri_regex};

/// Evaluates regular-expression URI match rules with bounded pattern size and execution time.
///
/// Each client caches compiled patterns until [`UriMatcherClient::clear`] or drop, so holders must
/// clear it on lock and logout.
#[derive(Default)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct UriMatcherClient {
    matcher: UriMatcher,
}

/// Results of [`UriMatcherClient::matches_batch`], one per pattern in input order.
#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi))]
#[serde(transparent)]
pub struct UriMatchResults(#[cfg_attr(feature = "wasm", tsify(type = "boolean[]"))] pub Vec<bool>);

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl UriMatcherClient {
    /// Returns whether `target` matches `pattern`, case-insensitively. Invalid, oversized, and
    /// too-expensive patterns never match.
    pub fn matches(&self, pattern: &str, target: &str) -> bool {
        self.matcher.matches(pattern, target)
    }

    /// Evaluates each pattern against `target` in one call, within a shared time budget. Patterns
    /// reached after the budget is spent never match.
    pub fn matches_batch(&self, patterns: Vec<String>, target: &str) -> UriMatchResults {
        UriMatchResults(self.matcher.matches_batch(&patterns, target))
    }

    /// Checks whether `pattern` can be saved as a regular-expression URI match rule.
    pub fn validate(&self, pattern: &str) -> Result<(), UriMatcherError> {
        validate_uri_regex(pattern)
    }

    /// Drops every cached pattern. Call on lock and logout, since patterns are vault data.
    pub fn clear(&self) {
        self.matcher.clear();
    }
}
