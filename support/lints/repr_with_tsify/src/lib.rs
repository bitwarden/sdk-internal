#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_data_structures;
extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use rustc_data_structures::fx::FxHashSet;
use rustc_hir::{
    def::{DefKind, Res},
    def_id::{DefId, LocalDefId},
    Item, ItemKind, QPath, Ty, TyKind,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::{ExpnKind, MacroKind};

const HELP: &str = "serde_repr serializes this as its `#[repr(..)]` integer, but Tsify \
                    generates a TypeScript type from the Rust shape — they disagree at \
                    the WASM boundary. Use `#[cfg_attr(feature = \"wasm\", wasm_bindgen)]` \
                    instead of Tsify for repr-encoded enums.";

dylint_linting::impl_late_lint! {
    /// ### What it does
    ///
    /// Warns when a type derives both `serde_repr::Serialize_repr` /
    /// `serde_repr::Deserialize_repr` and `tsify::Tsify`.
    ///
    /// ### Why is this bad?
    ///
    /// `serde_repr` derives serialize the type as its `#[repr(intN)]` integer,
    /// while `Tsify` generates a TypeScript declaration from the Rust shape
    /// (string-valued variants for enums by default). The TypeScript consumer
    /// therefore disagrees with the runtime wire format, producing a silent
    /// mismatch at the WASM boundary.
    ///
    /// For repr-encoded enums that need to cross the WASM boundary, use
    /// `#[cfg_attr(feature = "wasm", wasm_bindgen)]` instead of `Tsify` —
    /// `wasm_bindgen` natively supports integer-valued enums.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// #[derive(Serialize_repr, Deserialize_repr)]
    /// #[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
    /// #[repr(u8)]
    /// pub enum CollectionType { Shared = 0, Default = 1 }
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// #[derive(Serialize_repr, Deserialize_repr)]
    /// #[cfg_attr(feature = "wasm", wasm_bindgen)]
    /// #[repr(u8)]
    /// pub enum CollectionType { Shared = 0, Default = 1 }
    /// ```
    pub REPR_WITH_TSIFY,
    Warn,
    "deriving both serde_repr and tsify::Tsify produces a TS/wire-format mismatch",
    ReprWithTsify::default()
}

#[derive(Default)]
pub struct ReprWithTsify {
    has_repr_serde: FxHashSet<LocalDefId>,
    has_tsify: FxHashSet<LocalDefId>,
}

impl<'tcx> LateLintPass<'tcx> for ReprWithTsify {
    fn check_item(&mut self, _cx: &LateContext<'tcx>, item: &'tcx Item<'tcx>) {
        let ItemKind::Impl(impl_) = item.kind else {
            return;
        };
        let ExpnKind::Macro(MacroKind::Derive, derive_name) =
            item.span.ctxt().outer_expn_data().kind
        else {
            return;
        };
        let set = match last_segment(derive_name.as_str()) {
            "Tsify" => &mut self.has_tsify,
            "Serialize_repr" | "Deserialize_repr" => &mut self.has_repr_serde,
            _ => return,
        };
        let Some(self_did) = adt_def_id(impl_.self_ty).and_then(DefId::as_local) else {
            return;
        };
        set.insert(self_did);
    }

    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        let mut hits: Vec<LocalDefId> = self
            .has_tsify
            .intersection(&self.has_repr_serde)
            .copied()
            .collect();
        hits.sort_by_key(|did| cx.tcx.def_ident_span(did.to_def_id()));
        for did in hits {
            let Some(span) = cx.tcx.def_ident_span(did.to_def_id()) else {
                continue;
            };
            let name = cx.tcx.item_name(did.to_def_id());
            span_lint_and_help(
                cx,
                REPR_WITH_TSIFY,
                span,
                format!("`{name}` derives both `serde_repr` and `tsify::Tsify`"),
                None,
                HELP,
            );
        }
    }
}

fn adt_def_id(ty: &Ty<'_>) -> Option<DefId> {
    if let TyKind::Path(QPath::Resolved(_, path)) = &ty.kind {
        if let Res::Def(DefKind::Struct | DefKind::Enum | DefKind::Union, did) = path.res {
            return Some(did);
        }
    }
    None
}

fn last_segment(path: &str) -> &str {
    path.rsplit_once("::").map_or(path, |(_, tail)| tail)
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "ui");
}
