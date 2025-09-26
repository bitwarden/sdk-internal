#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::{diagnostics::span_lint, ty::implements_trait};
use rustc_hir::{Item, ItemKind};
use rustc_lint::LateLintPass;
use rustc_span::symbol::sym;

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
        if let ItemKind::Enum(_, _, enum_def) = &item.kind {
            let ty = cx.tcx.type_of(item.owner_id.def_id).instantiate_identity();
            let implements_error = cx
                .tcx
                .get_diagnostic_item(sym::Error)
                .map_or(false, |id| implements_trait(cx, ty, id, &[]));

            if !implements_error {
                return;
            }

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
