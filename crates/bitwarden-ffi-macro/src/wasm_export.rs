use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::{Attribute, ImplItem, ItemImpl, parse2};

/// Processes an impl block, transforming methods marked with `#[wasm_only]`.
///
/// For each marked method:
/// - Strips the `#[wasm_only]` marker attribute
/// - Renames the method with a `__wasm_only_` prefix (e.g. `subscribe` -> `__wasm_only_subscribe`)
/// - Adds `#[wasm_bindgen(js_name = "original_name")]` if no `js_name` is already present
/// - Adds `#[doc(hidden)]` to hide it from Rust documentation
/// - Adds `#[deprecated]` so it shows with strikethrough in IDE autocomplete
///
/// This makes the methods effectively unreachable from Rust (hidden, mangled name) while
/// preserving the original JS-facing API through `wasm_bindgen`'s `js_name` attribute.
pub(crate) fn wasm_export(item: TokenStream) -> TokenStream {
    let mut impl_block = match parse2::<ItemImpl>(item) {
        Ok(block) => block,
        Err(err) => return err.to_compile_error(),
    };

    for item in &mut impl_block.items {
        let ImplItem::Fn(method) = item else {
            continue;
        };

        let wasm_only_idx = method
            .attrs
            .iter()
            .position(|attr| attr.path().is_ident("wasm_only"));

        let Some(idx) = wasm_only_idx else {
            continue;
        };

        // Extract optional note from #[wasm_only(note = "custom note")] before removing
        let custom_note = match extract_wasm_only_note(&method.attrs[idx]) {
            Ok(note) => note,
            Err(err) => return err.to_compile_error(),
        };

        // Remove the #[wasm_only] marker attribute
        method.attrs.remove(idx);

        let original_name = method.sig.ident.to_string();

        // Add #[wasm_bindgen(js_name = "...")] if not already present,
        // so JS consumers still see the original name
        if !has_wasm_bindgen_js_name(&method.attrs) {
            method
                .attrs
                .push(syn::parse_quote!(#[wasm_bindgen(js_name = #original_name)]));
        }

        // Hide from Rust documentation
        method.attrs.push(syn::parse_quote!(#[doc(hidden)]));

        // Mark as deprecated so IDEs show strikethrough
        let note = custom_note.unwrap_or_else(|| {
            "This is a WASM-only binding. Calling it from Rust is not allowed.".to_string()
        });
        method
            .attrs
            .push(syn::parse_quote!(#[deprecated(note = #note)]));

        // Suppress the deprecation warning on the definition itself
        method.attrs.push(syn::parse_quote!(#[allow(deprecated)]));

        // Rename the method with __wasm_only_ prefix to discourage direct Rust usage
        method.sig.ident = syn::Ident::new(
            &format!("__wasm_only_{original_name}"),
            method.sig.ident.span(),
        );
    }

    impl_block.into_token_stream()
}

/// Extracts the optional note from `#[wasm_only(note = "custom note")]`.
/// Returns `None` for plain `#[wasm_only]`, or `Err` for unknown attributes.
fn extract_wasm_only_note(attr: &Attribute) -> Result<Option<String>, syn::Error> {
    // Plain #[wasm_only] with no arguments
    if attr.meta.require_path_only().is_ok() {
        return Ok(None);
    }

    let mut note = None;
    attr.parse_nested_meta(|meta| {
        if meta.path.is_ident("note") {
            note = Some(meta.value()?.parse::<syn::LitStr>()?.value());
            Ok(())
        } else {
            Err(meta.error("unknown attribute, expected `note`"))
        }
    })?;
    Ok(note)
}

fn has_wasm_bindgen_js_name(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("wasm_bindgen")
            && attr.to_token_stream().to_string().contains("js_name")
    })
}
