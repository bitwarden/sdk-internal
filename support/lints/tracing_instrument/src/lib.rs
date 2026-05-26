#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use rustc_hir::{ImplItem, Item, TraitItem};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{ExpnKind, MacroKind, Span};

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
    /// definition (the `tracing_attributes` crate), not by attribute path. This means every
    /// way to reach `tracing::instrument` is caught: the fully-qualified `#[tracing::instrument]`,
    /// the bare `#[instrument]` after `use tracing::instrument`, and aliased imports like
    /// `use tracing::instrument as foo; #[foo]`. Expansions emitted by our own
    /// `bitwarden_logging::instrument` wrapper (which internally re-emits `tracing::instrument`)
    /// are filtered out via a check against the wrapper crate (`bitwarden_logging_macro`) in
    /// the same backtrace.
    ///
    /// ### Default level
    ///
    /// Currently defaults to `Allow` to give existing call sites time to migrate without
    /// breaking CI (the workspace runs `cargo dylint` with `-D warnings`). Crates that have
    /// already been swept can opt in via `#![warn(tracing_instrument)]` (or `deny`) at the
    /// crate root. The default will flip to `Warn` once the workspace is clean.
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
    Allow,
    "use `bitwarden_logging::instrument` instead of `tracing::instrument`"
}

const TRACING_ATTRIBUTES_CRATE: &str = "tracing_attributes";
const WRAPPER_CRATE: &str = "bitwarden_logging_macro";

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
    let mut tracing_call_site: Option<Span> = None;
    let mut emitted_by_wrapper = false;

    for expn in span.macro_backtrace() {
        let ExpnKind::Macro(MacroKind::Attr, _) = expn.kind else {
            continue;
        };
        let Some(def_id) = expn.macro_def_id else {
            continue;
        };
        let crate_name = cx.tcx.crate_name(def_id.krate);
        match crate_name.as_str() {
            TRACING_ATTRIBUTES_CRATE => {
                // Only record the innermost `tracing::instrument` call site so the diagnostic
                // points at the attribute the user actually wrote.
                if tracing_call_site.is_none() {
                    tracing_call_site = Some(expn.call_site);
                }
            }
            WRAPPER_CRATE => {
                emitted_by_wrapper = true;
            }
            _ => {}
        }
    }

    if emitted_by_wrapper {
        return;
    }
    if let Some(call_site) = tracing_call_site {
        span_lint_and_help(
            cx,
            TRACING_INSTRUMENT,
            call_site,
            "use `bitwarden_logging::instrument` instead of `tracing::instrument`",
            None,
            "`bitwarden_logging::instrument` defaults to `skip_all`, preventing accidental \
             logging of function arguments. Use `fields(name = expr)` to opt in.",
        );
    }
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "ui");
}
