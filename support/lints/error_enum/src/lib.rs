#![feature(rustc_private)]
#![feature(let_chains)]
#![warn(unused_extern_crates)]

extern crate rustc_hir;

use clippy_utils::diagnostics::span_lint;
use rustc_hir::{Item, ItemKind};
use rustc_lint::LateLintPass;

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Warns when an enum variant name ends with "Error".
    ///
    /// ### Why is this bad?
    ///
    /// Enum variant names ending with "Error" can be redundant and verbose,
    /// especially when the enum itself represents error types. This can lead
    /// to awkward naming like `MyError::SomeError`.
    ///
    /// ### Example
    ///
    /// ```rust
    /// enum ApiError {
    ///     NetworkError,  // warns: variant ends with "Error"
    ///     TimeoutError,  // warns: variant ends with "Error"
    /// }
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust
    /// enum ApiError {
    ///     Network,
    ///     Timeout,
    /// }
    /// ```
    pub ENUM_VARIANT_ENDS_WITH_ERROR,
    Warn,
    "enum variant names should not end with 'Error'"
}

impl<'tcx> LateLintPass<'tcx> for EnumVariantEndsWithError {
    fn check_item(&mut self, cx: &rustc_lint::LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        if let ItemKind::Enum(enum_def, _) = &item.kind {
            for variant in enum_def.variants {
                let variant_name = variant.ident.name.as_str();
                if variant_name.ends_with("Error") {
                    span_lint(
                        cx,
                        ENUM_VARIANT_ENDS_WITH_ERROR,
                        variant.ident.span,
                        format!("enum variant `{}` ends with 'Error'", variant_name),
                    );
                }
            }
        }
    }
}

#[test]
fn ui() {
    dylint_testing::ui_test(env!("CARGO_PKG_NAME"), "ui");
}
