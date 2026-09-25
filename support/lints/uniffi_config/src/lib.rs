#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_ast;

use std::path::Path;

use clippy_utils::diagnostics::span_lint_and_help;
use rustc_ast::ast::{Item, ItemKind};
use rustc_lint::{EarlyContext, EarlyLintPass};

dylint_linting::declare_pre_expansion_lint! {
    /// ### What it does
    ///
    /// Warns when a crate calls `uniffi::setup_scaffolding!()` but has no
    /// `uniffi.toml` next to its `Cargo.toml`.
    ///
    /// ### Why is this bad?
    ///
    /// `uniffi.toml` is where the Kotlin package name and the Swift module
    /// names are set. Without it, `uniffi-bindgen` derives them from the crate
    /// name, so the crate lands in the mobile clients under a name that does
    /// not match the rest of the SDK, and it misses the shared binding options
    /// (`generate_immutable_records`, `omit_checksums`, `android`).
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// // crates/bitwarden-foo/src/lib.rs, with no crates/bitwarden-foo/uniffi.toml
    /// uniffi::setup_scaffolding!();
    /// ```
    ///
    /// Use instead: add `crates/bitwarden-foo/uniffi.toml`, copying the
    /// `[bindings.kotlin]` / `[bindings.swift]` layout from a neighboring
    /// crate and substituting this crate's names.
    pub MISSING_UNIFFI_CONFIG,
    Warn,
    "crates calling `uniffi::setup_scaffolding!()` must ship a `uniffi.toml`"
}

impl EarlyLintPass for MissingUniffiConfig {
    fn check_item(&mut self, cx: &EarlyContext<'_>, item: &Item) {
        if !is_setup_scaffolding(item) {
            return;
        }

        // Set by cargo for every crate it compiles, and dylint always runs under cargo.
        let Some(crate_dir) = std::env::var_os("CARGO_MANIFEST_DIR") else {
            return;
        };

        if Path::new(&crate_dir).join("uniffi.toml").is_file() {
            return;
        }

        span_lint_and_help(
            cx,
            MISSING_UNIFFI_CONFIG,
            item.span,
            "this crate sets up UniFFI scaffolding but has no `uniffi.toml`",
            None,
            "add a `uniffi.toml` beside `Cargo.toml`, copying the `[bindings.kotlin]` / `[bindings.swift]` layout from a neighboring crate and substituting this crate's names",
        );
    }
}

fn is_setup_scaffolding(item: &Item) -> bool {
    let ItemKind::MacCall(mac) = &item.kind else {
        return false;
    };
    let segments = &mac.path.segments;
    let Some(last) = segments.last() else {
        return false;
    };
    if last.ident.name.as_str() != "setup_scaffolding" {
        return false;
    }
    // Accept both `uniffi::setup_scaffolding!()` and an imported `setup_scaffolding!()`.
    match segments.len() {
        1 => true,
        len => segments[len - 2].ident.name.as_str() == "uniffi",
    }
}

#[test]
fn ui() {
    dylint_testing::ui_test_example(env!("CARGO_PKG_NAME"), "ui");
}
