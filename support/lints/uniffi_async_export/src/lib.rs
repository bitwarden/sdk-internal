#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_ast;
extern crate rustc_errors;

use clippy_utils::diagnostics::{span_lint_and_help, span_lint_and_sugg};
use rustc_ast::ast::{
    AssocItemKind, AttrArgs, AttrKind, Attribute, CoroutineKind, FnSig, Item, ItemKind,
};
use rustc_ast::token::{LitKind, TokenKind};
use rustc_ast::tokenstream::TokenTree;
use rustc_errors::Applicability;
use rustc_lint::{EarlyContext, EarlyLintPass};

dylint_linting::declare_pre_expansion_lint! {
    /// ### What it does
    ///
    /// Warns when `#[uniffi::export]` is applied to an `async fn` (either a
    /// free function or any `async fn` inside an `impl` block) without
    /// specifying `async_runtime = "tokio"`.
    ///
    /// ### Why is this bad?
    ///
    /// UniFFI requires an explicit async runtime when exporting `async fn`s.
    /// Omitting it produces non-functional bindings or compile errors
    /// downstream when generating mobile bindings.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// #[uniffi::export]
    /// impl Foo {
    ///     async fn bar(&self) {}
    /// }
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// #[uniffi::export(async_runtime = "tokio")]
    /// impl Foo {
    ///     async fn bar(&self) {}
    /// }
    /// ```
    pub UNIFFI_ASYNC_EXPORT,
    Warn,
    "`#[uniffi::export]` on `async fn`s must specify `async_runtime = \"tokio\"`"
}

impl EarlyLintPass for UniffiAsyncExport {
    fn check_item(&mut self, cx: &EarlyContext<'_>, item: &Item) {
        let Some(attr) = item.attrs.iter().find(|a| is_uniffi_export(a)) else {
            return;
        };

        let has_async = match &item.kind {
            ItemKind::Impl(impl_) => contains_async_fn(impl_),
            ItemKind::Fn(fn_) => is_async(&fn_.sig),
            _ => return,
        };

        if !has_async {
            return;
        }

        if has_async_runtime_tokio(attr) {
            return;
        }

        emit_lint(cx, attr);
    }
}

fn is_async(sig: &FnSig) -> bool {
    matches!(sig.header.coroutine_kind, Some(CoroutineKind::Async { .. }))
}

fn is_uniffi_export(attr: &Attribute) -> bool {
    let AttrKind::Normal(normal) = &attr.kind else {
        return false;
    };
    let segments = &normal.item.path.segments;
    let len = segments.len();
    len >= 2
        && segments[len - 2].ident.name.as_str() == "uniffi"
        && segments[len - 1].ident.name.as_str() == "export"
}

fn contains_async_fn(impl_: &rustc_ast::ast::Impl) -> bool {
    impl_.items.iter().any(|assoc| {
        let AssocItemKind::Fn(fn_) = &assoc.kind else {
            return false;
        };
        is_async(&fn_.sig)
    })
}

fn has_async_runtime_tokio(attr: &Attribute) -> bool {
    let AttrKind::Normal(normal) = &attr.kind else {
        return false;
    };
    let AttrArgs::Delimited(delim) = &normal.item.args else {
        return false;
    };

    let trees: Vec<&TokenTree> = delim.tokens.iter().collect();
    trees.windows(3).any(|w| {
        let is_async_runtime_ident = matches!(
            w[0],
            TokenTree::Token(t, _) if matches!(t.kind, TokenKind::Ident(name, _) if name.as_str() == "async_runtime")
        );
        let is_eq = matches!(w[1], TokenTree::Token(t, _) if matches!(t.kind, TokenKind::Eq));
        let is_tokio_str = matches!(
            w[2],
            TokenTree::Token(t, _) if matches!(
                t.kind,
                TokenKind::Literal(lit) if lit.kind == LitKind::Str && lit.symbol.as_str() == "tokio"
            )
        );
        is_async_runtime_ident && is_eq && is_tokio_str
    })
}

fn emit_lint(cx: &EarlyContext<'_>, attr: &Attribute) {
    let AttrKind::Normal(normal) = &attr.kind else {
        return;
    };
    let msg =
        "`#[uniffi::export]` on `async fn`s must specify `async_runtime = \"tokio\"`";

    if matches!(normal.item.args, AttrArgs::Empty) {
        span_lint_and_sugg(
            cx,
            UNIFFI_ASYNC_EXPORT,
            attr.span,
            msg,
            "specify the tokio async runtime",
            "#[uniffi::export(async_runtime = \"tokio\")]".to_string(),
            Applicability::MachineApplicable,
        );
    } else {
        span_lint_and_help(
            cx,
            UNIFFI_ASYNC_EXPORT,
            attr.span,
            msg,
            None,
            "add `async_runtime = \"tokio\"` to the attribute arguments",
        );
    }
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "ui");
}
