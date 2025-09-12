#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_hir;
extern crate rustc_span;
use clippy_utils::{diagnostics::span_lint, ty::implements_trait};
use rustc_hir::{Item, ItemKind};
use rustc_lint::LateLintPass;
use rustc_span::symbol::sym;

dylint_linting::declare_late_lint! {
    pub ERROR_SUFFIX,
    Warn,
    "enums and structs implementing Error should end with 'Error'"
}

impl<'tcx> LateLintPass<'tcx> for ErrorSuffix {
    fn check_item(&mut self, cx: &rustc_lint::LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        let ident = match item.kind {
            ItemKind::Enum(ident, ..) | ItemKind::Struct(ident, ..) => ident,
            _ => return,
        };

        let item_name = ident.name.as_str();

        match &item.kind {
            ItemKind::Enum(..) | ItemKind::Struct(..) => {
                let ty = cx.tcx.type_of(item.owner_id.def_id).instantiate_identity();
                let implements_error = cx
                    .tcx
                    .get_diagnostic_item(sym::Error)
                    .map_or(false, |id| implements_trait(cx, ty, id, &[]));

                if implements_error && !item_name.ends_with("Error") {
                    let item_type = match &item.kind {
                        ItemKind::Enum(..) => "enum",
                        ItemKind::Struct(..) => "struct",
                        _ => unreachable!(),
                    };

                    span_lint(
                        cx,
                        ERROR_SUFFIX,
                        ident.span,
                        format!(
                            "{} `{}` implements Error but doesn't end with 'Error'",
                            item_type, item_name
                        ),
                    );
                }
            }
            _ => {}
        }
    }
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "ui");
}
