use proc_macro2::TokenStream;
use quote::quote;
use syn::{Attribute, ImplItem, ItemFn, ItemImpl, Signature, Visibility, parse2, spanned::Spanned};

use crate::attrs;

/// Applies `#[wasm_bindgen]` to an impl block or a free function, forwarding this macro's
/// arguments to it, and rewrites the methods marked `#[wasm_only]`.
pub(crate) fn wasm_export(attr: TokenStream, item: TokenStream) -> TokenStream {
    match parse2::<ItemImpl>(item.clone()) {
        Ok(impl_block) => wasm_export_impl(attr, impl_block),
        // An impl block is by far the common case, so its parse error is the one worth reporting
        // when the item is neither.
        Err(impl_err) => match parse2::<ItemFn>(item) {
            Ok(function) => wasm_export_fn(attr, function),
            Err(_) => impl_err.to_compile_error(),
        },
    }
}

/// `#[wasm_export]` on an impl block: the block takes the attribute, and each method keeps the
/// `#[wasm_bindgen(..)]` it declares for itself.
fn wasm_export_impl(attr: TokenStream, mut impl_block: ItemImpl) -> TokenStream {
    let forwarded = match attrs::parse_args(attr) {
        Ok(args) => args,
        Err(err) => return err.to_compile_error(),
    };

    if let Err(err) = check_exportable(&impl_block.generics, &impl_block.attrs, "impl blocks") {
        return err.to_compile_error();
    }

    for item in &mut impl_block.items {
        let ImplItem::Fn(method) = item else { continue };

        // Applied before the visibility check so the marker is never silently dropped: on a
        // private method it still renames and deprecates.
        let renamed = match apply_wasm_only(&mut method.attrs, &mut method.sig) {
            Ok(renamed) => renamed,
            Err(err) => return err.to_compile_error(),
        };

        // wasm_bindgen exports every `pub` method in the block and ignores the rest, so a private
        // generic helper is allowed to stay.
        if !matches!(method.vis, Visibility::Public(_)) {
            continue;
        }

        if !method.sig.generics.params.is_empty() {
            return syn::Error::new(
                method.sig.generics.span(),
                "#[wasm_export] does not support generic methods; wasm_bindgen cannot export them",
            )
            .to_compile_error();
        }

        if let Some(name) = renamed {
            // A constructor is named by wasm_bindgen itself, which rejects a `js_name` on one.
            let named = method
                .attrs
                .iter()
                .filter_map(attrs::wasm_bindgen_args)
                .flatten()
                .any(|meta| meta.path().is_ident("js_name") || meta.path().is_ident("constructor"));
            if !named {
                method.attrs.push(syn::parse_quote!(
                    #[cfg_attr(feature = "wasm", wasm_bindgen(js_name = #name))]
                ));
            }
        }
    }

    let bindgen = attrs::wasm_bindgen_attr(&forwarded);
    quote! {
        #bindgen
        #impl_block
    }
}

/// `#[wasm_export]` on a free function, which carries a single `#[wasm_bindgen(..)]`.
fn wasm_export_fn(attr: TokenStream, mut function: ItemFn) -> TokenStream {
    let mut forwarded = match attrs::parse_args(attr) {
        Ok(args) => args,
        Err(err) => return err.to_compile_error(),
    };

    if let Err(err) = check_exportable(&function.sig.generics, &function.attrs, "functions") {
        return err.to_compile_error();
    }

    let renamed = match apply_wasm_only(&mut function.attrs, &mut function.sig) {
        Ok(renamed) => renamed,
        Err(err) => return err.to_compile_error(),
    };

    // There is no second attribute to put the JS name on, so it joins this macro's arguments.
    if let Some(name) = renamed {
        let named = forwarded.iter().any(|meta| meta.path().is_ident("js_name"));
        if !named {
            forwarded.push(syn::parse_quote!(js_name = #name));
        }
    }

    let bindgen = attrs::wasm_bindgen_attr(&forwarded);
    quote! {
        #bindgen
        #function
    }
}

/// Rejects a generic item, which wasm_bindgen cannot export, and a leftover `#[wasm_bindgen]`.
///
/// `kind` names the item in the error, plural, as in "generic impl blocks".
fn check_exportable(
    generics: &syn::Generics,
    item_attrs: &[Attribute],
    kind: &str,
) -> syn::Result<()> {
    if !generics.params.is_empty() {
        return Err(syn::Error::new(
            generics.span(),
            format!(
                "#[wasm_export] does not support generic {kind}; wasm_bindgen cannot export them"
            ),
        ));
    }

    if let Some(attr) = attrs::find_wasm_bindgen(item_attrs) {
        return Err(syn::Error::new_spanned(
            attr,
            "#[wasm_export] replaces #[wasm_bindgen]; pass its arguments to #[wasm_export] \
             instead, as in #[wasm_export(js_class = Foo)]",
        ));
    }

    Ok(())
}

/// Applies `#[wasm_only]`, if present, returning the name the item had.
///
/// The marker means JavaScript is the only intended caller. Rename the function so Rust callers do
/// not reach for it, hide it from documentation, and deprecate it so any that do get a warning and
/// see it struck through in autocomplete. The JS name is unaffected, and the caller declares it.
fn apply_wasm_only(attrs: &mut Vec<Attribute>, sig: &mut Signature) -> syn::Result<Option<String>> {
    let idx = attrs.iter().position(|a| a.path().is_ident("wasm_only"));
    let Some(idx) = idx else { return Ok(None) };
    let note = wasm_only_note(&attrs.remove(idx))?;

    let original = sig.ident.to_string();
    attrs.push(syn::parse_quote!(#[doc(hidden)]));
    attrs.push(syn::parse_quote!(#[deprecated(note = #note)]));
    attrs.push(syn::parse_quote!(#[allow(deprecated)]));
    sig.ident = syn::Ident::new(&format!("__wasm_only_{original}"), sig.ident.span());

    Ok(Some(original))
}

/// Reads the deprecation note from `#[wasm_only]` / `#[wasm_only(note = "...")]`.
fn wasm_only_note(attr: &Attribute) -> syn::Result<String> {
    const DEFAULT: &str = "This is a WASM-only binding. Calling it from Rust is not allowed.";
    if attr.meta.require_path_only().is_ok() {
        return Ok(DEFAULT.to_owned());
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
    Ok(note.unwrap_or_else(|| DEFAULT.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expansion with the whitespace `TokenStream::to_string` inserts between tokens removed, so
    /// assertions can be written the way the code is.
    fn expand(attr: TokenStream, item: TokenStream) -> String {
        wasm_export(attr, item).to_string().replace(' ', "")
    }

    #[test]
    fn applies_wasm_bindgen_to_the_block_under_the_wasm_feature() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl Canvas {
                    pub fn translate(&self, point: Point) -> Point { point }
                }
            },
        );

        assert!(!out.contains("compile_error!"), "{out}");
        assert!(
            out.contains("#[cfg_attr(feature=\"wasm\",::bitwarden_ffi::_macro::wasm_bindgen)]"),
            "{out}"
        );
        // The method is left exactly as written.
        assert!(
            out.contains("pubfntranslate(&self,point:Point)->Point{point}"),
            "{out}"
        );
    }

    #[test]
    fn forwards_its_arguments_to_wasm_bindgen() {
        let out = expand(
            quote!(js_class = IpcClient),
            quote! {
                impl JsIpcClient {
                    pub fn is_running(&self) -> bool { true }
                }
            },
        );

        assert!(
            out.contains("::bitwarden_ffi::_macro::wasm_bindgen(js_class=IpcClient)"),
            "{out}"
        );
    }

    #[test]
    fn renames_a_wasm_only_method_and_keeps_its_js_name() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl JsIpcClient {
                    #[wasm_only]
                    pub fn is_running(&self) -> bool { true }
                }
            },
        );

        assert!(out.contains("fn__wasm_only_is_running"), "{out}");
        assert!(
            out.contains("#[cfg_attr(feature=\"wasm\",wasm_bindgen(js_name=\"is_running\"))]"),
            "{out}"
        );
        assert!(out.contains("#[doc(hidden)]"), "{out}");
        assert!(
            out.contains(
                "#[deprecated(note=\"ThisisaWASM-onlybinding.CallingitfromRustisnotallowed.\")]"
            ),
            "{out}"
        );
        assert!(out.contains("#[allow(deprecated)]"), "{out}");
    }

    #[test]
    fn carries_a_custom_note() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl JsIpcClient {
                    #[wasm_only(note = "Use `IpcClient::start`.")]
                    pub fn start(&self) {}
                }
            },
        );

        assert!(
            out.contains("#[deprecated(note=\"Use`IpcClient::start`.\")]"),
            "{out}"
        );
    }

    #[test]
    fn keeps_a_js_name_the_method_already_declares() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl JsIpcClient {
                    #[wasm_only]
                    #[wasm_bindgen(js_name = isRunning)]
                    pub fn is_running(&self) -> bool { true }
                }
            },
        );

        assert!(out.contains("#[wasm_bindgen(js_name=isRunning)]"), "{out}");
        assert!(!out.contains("js_name=\"is_running\""), "{out}");
    }

    #[test]
    fn keeps_a_js_name_the_method_declares_under_a_cfg_attr() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl PolicyClient {
                    #[wasm_only]
                    #[cfg_attr(feature = "wasm", wasm_bindgen(js_name = "get_enforced"))]
                    pub fn get_enforced(&self) {}
                }
            },
        );

        assert_eq!(out.matches("js_name=").count(), 1, "{out}");
        assert!(out.contains("js_name=\"get_enforced\""), "{out}");
    }

    #[test]
    fn leaves_a_wasm_only_constructor_for_wasm_bindgen_to_name() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl JsIpcClient {
                    #[wasm_only]
                    #[wasm_bindgen(constructor)]
                    pub fn new() -> JsIpcClient { todo!() }
                }
            },
        );

        assert!(!out.contains("js_name"), "{out}");
        assert!(out.contains("fn__wasm_only_new"), "{out}");
    }

    #[test]
    fn renames_a_private_wasm_only_method_without_naming_it_for_javascript() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl JsIpcClient {
                    #[wasm_only]
                    fn internal(&self) {}
                }
            },
        );

        assert!(out.contains("fn__wasm_only_internal"), "{out}");
        assert!(!out.contains("js_name"), "{out}");
    }

    #[test]
    fn leaves_a_private_generic_method_alone() {
        // wasm_bindgen only exports `pub` methods, so a private helper may stay generic.
        let out = expand(
            TokenStream::new(),
            quote! {
                impl Canvas {
                    fn draw<T: Shape>(&self, shape: T) {}
                }
            },
        );

        assert!(!out.contains("compile_error!"), "{out}");
    }

    #[test]
    fn rejects_a_generic_impl_block() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl<T> Canvas<T> {
                    pub fn translate(&self, point: Point) -> Point { point }
                }
            },
        );

        assert!(out.contains("compile_error!"), "{out}");
        assert!(out.contains("doesnotsupportgenericimplblocks"), "{out}");
    }

    #[test]
    fn rejects_a_generic_method() {
        let out = expand(
            TokenStream::new(),
            quote! {
                impl Canvas {
                    pub fn draw<T: Shape>(&self, shape: T) {}
                }
            },
        );

        assert!(out.contains("compile_error!"), "{out}");
        assert!(out.contains("doesnotsupportgenericmethods"), "{out}");
    }

    #[test]
    fn rejects_a_block_that_still_carries_wasm_bindgen() {
        // The macro stands in for the attribute rather than decorating it, so leaving one behind
        // would export every method twice.
        let out = expand(
            TokenStream::new(),
            quote! {
                #[wasm_bindgen(js_class = IpcClient)]
                impl JsIpcClient {
                    pub fn is_running(&self) -> bool { true }
                }
            },
        );

        assert!(out.contains("compile_error!"), "{out}");
        assert!(out.contains("replaces#[wasm_bindgen]"), "{out}");
    }

    #[test]
    fn exports_a_free_function() {
        let out = expand(
            quote!(js_name = doThing),
            quote! {
                pub fn do_thing(point: Point) -> Point { point }
            },
        );

        assert!(!out.contains("compile_error!"), "{out}");
        assert!(
            out.contains("::bitwarden_ffi::_macro::wasm_bindgen(js_name=doThing)"),
            "{out}"
        );
        assert!(out.contains("pubfndo_thing"), "{out}");
    }

    #[test]
    fn names_a_wasm_only_free_function_in_its_own_arguments() {
        let out = expand(
            TokenStream::new(),
            quote! {
                #[wasm_only]
                pub fn do_thing() {}
            },
        );

        assert!(
            out.contains("::bitwarden_ffi::_macro::wasm_bindgen(js_name=\"do_thing\")"),
            "{out}"
        );
        assert!(out.contains("pubfn__wasm_only_do_thing"), "{out}");
    }

    #[test]
    fn rejects_a_generic_free_function() {
        let out = expand(
            TokenStream::new(),
            quote! {
                pub fn do_thing<T>(value: T) {}
            },
        );

        assert!(out.contains("compile_error!"), "{out}");
        assert!(out.contains("doesnotsupportgenericfunctions"), "{out}");
    }

    #[test]
    fn rejects_an_item_that_is_neither() {
        let out = expand(TokenStream::new(), quote! { pub struct Canvas; });

        assert!(out.contains("compile_error!"), "{out}");
    }
}
