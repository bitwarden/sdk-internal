use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::{ForeignItem, ItemForeignMod, parse2};

use crate::attrs;

/// Declares a block of JavaScript imports, forwarding this macro's arguments to `#[wasm_bindgen]`,
/// and implements the wire traits for each `type` it declares so the type crosses as itself.
pub(crate) fn wasm_import(attr: TokenStream, item: TokenStream) -> TokenStream {
    let forwarded = match attrs::parse_args(attr) {
        Ok(args) => args,
        Err(err) => return err.to_compile_error(),
    };

    let block = match parse2::<ItemForeignMod>(item.clone()) {
        Ok(block) => block,
        Err(_) => {
            return syn::Error::new_spanned(item, "#[wasm_import] applies to an `extern \"C\"` block")
                .to_compile_error();
        }
    };

    if let Some(attr) = attrs::find_wasm_bindgen(&block.attrs) {
        return syn::Error::new_spanned(attr, "#[wasm_import] replaces #[wasm_bindgen]; remove it")
            .to_compile_error();
    }

    // The block's own `cfg`s gate the generated impls too, or they would name a type that does not
    // exist.
    let cfgs: Vec<_> = block
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("cfg"))
        .collect();
    let wire_impls = block.items.iter().filter_map(|item| match item {
        ForeignItem::Type(ty) => {
            let ident = &ty.ident;
            Some(quote! {
                #(#cfgs)*
                ::bitwarden_ffi::impl_wire_object!(#ident);
            })
        }
        _ => None,
    });

    let call = if forwarded.is_empty() {
        quote!(wasm_bindgen)
    } else {
        quote!(wasm_bindgen(#forwarded))
    };
    let body = block.to_token_stream();
    // Unconditional, unlike the other macros: a `type` in an extern block only compiles once
    // wasm_bindgen rewrites it, and some blocks are gated on `target_arch` rather than `wasm`.
    quote! {
        #[::wasm_bindgen::prelude::#call]
        #body

        #(#wire_impls)*
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expand(attr: TokenStream, item: TokenStream) -> String {
        wasm_import(attr, item).to_string().replace(' ', "")
    }

    #[test]
    fn applies_wasm_bindgen_and_implements_the_wire_traits_per_type() {
        let out = expand(
            TokenStream::new(),
            quote! {
                extern "C" {
                    pub type Driver;
                    pub type Signal;

                    #[wasm_bindgen(method)]
                    pub fn lock(this: &Driver);
                }
            },
        );

        assert!(!out.contains("compile_error!"), "{out}");
        assert!(out.contains("#[::wasm_bindgen::prelude::wasm_bindgen]"), "{out}");
        assert!(out.contains("::bitwarden_ffi::impl_wire_object!(Driver);"), "{out}");
        assert!(out.contains("::bitwarden_ffi::impl_wire_object!(Signal);"), "{out}");
        assert!(!out.contains("impl_wire_object!(lock)"), "{out}");
    }

    #[test]
    fn forwards_arguments_to_wasm_bindgen() {
        let out = expand(
            quote!(module = "/js/driver.js"),
            quote! {
                extern "C" {
                    pub type Driver;
                }
            },
        );

        assert!(
            out.contains("#[::wasm_bindgen::prelude::wasm_bindgen(module=\"/js/driver.js\")]"),
            "{out}"
        );
    }

    #[test]
    fn gates_the_wire_impls_on_the_blocks_cfg() {
        let out = expand(
            TokenStream::new(),
            quote! {
                #[cfg(target_arch = "wasm32")]
                extern "C" {
                    pub type Driver;
                }
            },
        );

        assert!(
            out.contains(
                "#[cfg(target_arch=\"wasm32\")]::bitwarden_ffi::impl_wire_object!(Driver);"
            ),
            "{out}"
        );
    }

    #[test]
    fn a_block_without_types_implements_nothing() {
        let out = expand(
            TokenStream::new(),
            quote! {
                extern "C" {
                    pub fn log(message: &str);
                }
            },
        );

        assert!(!out.contains("impl_wire_object"), "{out}");
    }

    #[test]
    fn rejects_an_item_that_is_not_an_extern_block() {
        let out = expand(TokenStream::new(), quote! { pub struct Driver; });

        assert!(out.contains("compile_error!"), "{out}");
        assert!(out.contains("appliestoan`extern\\\"C\\\"`block"), "{out}");
    }

    #[test]
    fn rejects_a_block_that_already_has_wasm_bindgen() {
        let out = expand(
            TokenStream::new(),
            quote! {
                #[wasm_bindgen]
                extern "C" {
                    pub type Driver;
                }
            },
        );

        assert!(out.contains("compile_error!"), "{out}");
        assert!(out.contains("replaces#[wasm_bindgen]"), "{out}");
    }
}
