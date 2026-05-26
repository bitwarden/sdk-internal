#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_ast;

use clippy_utils::diagnostics::span_lint_and_help;
use rustc_ast::ast::{AttrKind, Attribute};
use rustc_lint::{EarlyContext, EarlyLintPass};

dylint_linting::declare_pre_expansion_lint! {
    /// ### What it does
    ///
    /// Warns when `#[tracing::instrument]` or a bare `#[instrument]` is used. Bitwarden code
    /// must use the fully-qualified `#[bitwarden_logging::instrument]`, which defaults to
    /// `skip_all` so function arguments are excluded from span fields unless explicitly
    /// opted in via `fields(...)`.
    ///
    /// ### Why is this bad?
    ///
    /// `tracing::instrument` records every argument that implements `Display`/`Debug` by
    /// default. In a vault-handling SDK this is a foot-gun: forgetting `skip_all` on a
    /// function like `derive_master_key(password, ...)` would log the user's password.
    ///
    /// Bare `#[instrument]` is also flagged because `use tracing::instrument;` is the
    /// classic way to re-introduce the foot-gun without any visible `tracing::` prefix
    /// at the call site. Always write the fully-qualified path so the safety property
    /// is visible.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// #[tracing::instrument]
    /// fn derive_master_key(password: &str) {}
    ///
    /// use tracing::instrument;
    /// #[instrument]
    /// fn derive_master_key_2(password: &str) {}
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// #[bitwarden_logging::instrument]
    /// fn derive_master_key(password: &str) {}
    /// ```
    pub TRACING_INSTRUMENT,
    Warn,
    "use the fully-qualified `#[bitwarden_logging::instrument]` instead of `#[tracing::instrument]` or bare `#[instrument]`"
}

impl EarlyLintPass for TracingInstrument {
    fn check_attribute(&mut self, cx: &EarlyContext<'_>, attr: &Attribute) {
        if !is_tracing_instrument(attr) {
            return;
        }

        span_lint_and_help(
            cx,
            TRACING_INSTRUMENT,
            attr.span,
            "use the fully-qualified `#[bitwarden_logging::instrument]` instead",
            None,
            "`bitwarden_logging::instrument` defaults to `skip_all`, preventing accidental \
             logging of function arguments. Use `fields(name = expr)` to opt in. \
             Always write the path fully so the safety property is visible at the call site.",
        );
    }
}

/// Matches `#[tracing::instrument]` (qualified) and `#[instrument]` (bare).
///
/// Bare `#[instrument]` is flagged because the most common way to re-introduce the
/// `tracing::instrument` foot-gun is `use tracing::instrument;` followed by an unqualified
/// `#[instrument]` attribute. Forcing the fully-qualified `#[bitwarden_logging::instrument]`
/// at every call site makes the safety property visible and the deviation lintable.
///
/// Renamed imports (`use tracing::instrument as foo;`) are not caught — those are explicit
/// enough that we treat them as opt-out.
fn is_tracing_instrument(attr: &Attribute) -> bool {
    let AttrKind::Normal(normal) = &attr.kind else {
        return false;
    };
    let segments = &normal.item.path.segments;
    match segments.len() {
        1 => segments[0].ident.name.as_str() == "instrument",
        2 => {
            segments[0].ident.name.as_str() == "tracing"
                && segments[1].ident.name.as_str() == "instrument"
        }
        _ => false,
    }
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "ui");
}
