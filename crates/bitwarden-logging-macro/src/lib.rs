//! Proc-macro wrapper around [`tracing::instrument`] that enforces `skip_all` by default.
//!
//! Use via the [`bitwarden_logging::instrument`](../bitwarden_logging/attr.instrument.html)
//! re-export rather than depending on this crate directly.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Meta, Token, parse::Parser, punctuated::Punctuated};

const REJECT_MSG: &str = "`#[bitwarden_logging::instrument]` enforces `skip_all` by default. \
    Use `fields(name = expr)` to opt in to logging specific arguments.";

/// Drop-in replacement for `#[tracing::instrument]` that defaults to `skip_all`, making
/// field logging opt-in.
///
/// Pass `fields(name = expr)` to record specific values. All other `tracing::instrument`
/// options (`name`, `level`, `target`, `ret`, `err`, `parent`, `follows_from`) flow through
/// unchanged.
///
/// User-supplied `skip(...)` or `skip_all` are rejected at compile time: `skip_all` is
/// already enforced and `fields(...)` is the way to opt back in.
#[proc_macro_attribute]
pub fn instrument(attr: TokenStream, item: TokenStream) -> TokenStream {
    let item2: TokenStream2 = item.into();

    let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
    let args = match parser.parse(attr) {
        Ok(args) => args,
        Err(e) => {
            let err = e.to_compile_error();
            return quote! { #err #item2 }.into();
        }
    };

    let mut errors = TokenStream2::new();
    for meta in &args {
        let Some(last) = meta.path().segments.last() else {
            continue;
        };
        if last.ident == "skip" || last.ident == "skip_all" {
            errors.extend(syn::Error::new_spanned(meta, REJECT_MSG).to_compile_error());
        }
    }

    if !errors.is_empty() {
        return quote! { #errors #item2 }.into();
    }

    let args_iter = args.iter();
    quote! {
        #[::tracing::instrument(skip_all #(, #args_iter)*)]
        #item2
    }
    .into()
}
