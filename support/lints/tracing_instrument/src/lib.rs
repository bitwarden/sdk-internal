#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_errors;
extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::diagnostics::{span_lint_and_help, span_lint_and_sugg};
use quote::ToTokens;
use rustc_errors::Applicability;
use rustc_hir::{ImplItem, Item, TraitItem};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_span::{ExpnKind, MacroKind, Span};
use syn::{Meta, Token, parse::Parser, punctuated::Punctuated};

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Warns when `tracing::instrument` is used as an attribute macro. Bitwarden code must
    /// use `bitwarden_logging::instrument` instead, which defaults to `skip_all` so function
    /// arguments are excluded from span fields unless explicitly opted in via `fields(...)`.
    ///
    /// ### Matching
    ///
    /// The lint inspects the post-expansion macro backtrace and matches by the macro's
    /// definition (the `tracing_attributes` crate), not by attribute path. Every way to reach
    /// `tracing::instrument` is caught: the fully-qualified `#[tracing::instrument]`, the
    /// bare `#[instrument]` after `use tracing::instrument`, and aliased imports like
    /// `use tracing::instrument as foo; #[foo]`.
    ///
    /// The `bitwarden_logging::instrument` wrapper internally re-emits `tracing::instrument`.
    /// It opts out of this lint at its emission site by including
    /// `#[allow(unknown_lints, tracing_instrument)]`, so wrappers don't need a special case
    /// here.
    ///
    /// ### Suggestions
    ///
    /// When the attribute does not use `skip(...)`, the lint emits a machine-applicable
    /// suggestion that swaps the path to `bitwarden_logging::instrument` and drops a
    /// redundant `skip_all` if present. When `skip(...)` is present the lint emits a
    /// help-only diagnostic, because translating a skip list into the wrapper's opt-in
    /// `fields(...)` model needs human judgment (the original may have been implicitly
    /// logging the non-skipped args).
    ///
    /// ### Default level
    ///
    /// Defaults to `Warn`: the workspace has been swept to `bitwarden_logging::instrument`, so
    /// any new `tracing::instrument` is flagged (the workspace runs `cargo dylint` with
    /// `-D warnings`). `bitwarden-crypto` is temporarily opted out via
    /// `#![allow(unknown_lints, tracing_instrument)]` at its crate root, because its
    /// `dangerous-crypto-debug` instrumentation intentionally logs key material and is migrated
    /// separately.
    ///
    /// ### Why is this bad?
    ///
    /// `tracing::instrument` records every argument that implements `Display`/`Debug` by
    /// default. In a vault-handling SDK this is a foot-gun: forgetting `skip_all` on a
    /// function like `derive_master_key(password, ...)` would log the user's password.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// #[tracing::instrument]
    /// fn derive_master_key(password: &str) {}
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// use bitwarden_logging::instrument;
    ///
    /// #[instrument]
    /// fn derive_master_key(password: &str) {}
    /// ```
    pub TRACING_INSTRUMENT,
    Warn,
    "use `bitwarden_logging::instrument` instead of `tracing::instrument`"
}

const TRACING_ATTRIBUTES_CRATE: &str = "tracing_attributes";
const LINT_MESSAGE: &str = "use `bitwarden_logging::instrument` instead of `tracing::instrument`";

impl<'tcx> LateLintPass<'tcx> for TracingInstrument {
    fn check_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        check_span(cx, item.span);
    }

    fn check_impl_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx ImplItem<'tcx>) {
        check_span(cx, item.span);
    }

    fn check_trait_item(&mut self, cx: &LateContext<'tcx>, item: &'tcx TraitItem<'tcx>) {
        check_span(cx, item.span);
    }
}

fn check_span(cx: &LateContext<'_>, span: Span) {
    let call_site = span.macro_backtrace().find_map(|expn| {
        let ExpnKind::Macro(MacroKind::Attr, _) = expn.kind else {
            return None;
        };
        let def_id = expn.macro_def_id?;
        (cx.tcx.crate_name(def_id.krate).as_str() == TRACING_ATTRIBUTES_CRATE)
            .then_some(expn.call_site)
    });

    let Some(call_site) = call_site else {
        return;
    };

    match build_suggestion(cx, call_site) {
        Some(replacement) => {
            span_lint_and_sugg(
                cx,
                TRACING_INSTRUMENT,
                call_site,
                LINT_MESSAGE,
                "replace with",
                replacement,
                Applicability::MachineApplicable,
            );
        }
        None => {
            span_lint_and_help(
                cx,
                TRACING_INSTRUMENT,
                call_site,
                LINT_MESSAGE,
                None,
                "`bitwarden_logging::instrument` defaults to `skip_all`, so the existing \
                 `skip(...)` list may need translation into `fields(name = expr)` opt-ins \
                 for arguments that should still be logged.",
            );
        }
    }
}

/// Builds a machine-applicable replacement for the `#[tracing::instrument(...)]` attribute.
///
/// Returns `None` when the existing args contain `skip(...)`, since that case needs human
/// judgment to decide which (if any) of the skipped/non-skipped args become `fields(...)`
/// opt-ins under the wrapper's `skip_all` default.
fn build_suggestion(cx: &LateContext<'_>, call_site: Span) -> Option<String> {
    let snippet = cx.sess().source_map().span_to_snippet(call_site).ok()?;
    let inner = snippet.strip_prefix("#[")?.strip_suffix(']')?.trim();

    let args_text = match inner.find('(') {
        None => return Some("#[bitwarden_logging::instrument]".to_string()),
        Some(open) => inner[open + 1..].strip_suffix(')')?,
    };

    let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
    let args = Parser::parse_str(parser, args_text).ok()?;

    if args
        .iter()
        .any(|m| matches!(m, Meta::List(l) if l.path.is_ident("skip")))
    {
        return None;
    }

    let kept: Vec<String> = args
        .iter()
        .filter(|m| !matches!(m, Meta::Path(p) if p.is_ident("skip_all")))
        .map(|m| m.to_token_stream().to_string())
        .collect();

    Some(if kept.is_empty() {
        "#[bitwarden_logging::instrument]".to_string()
    } else {
        format!("#[bitwarden_logging::instrument({})]", kept.join(", "))
    })
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "ui");
}
