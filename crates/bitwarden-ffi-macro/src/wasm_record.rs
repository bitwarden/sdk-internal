use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::{Item, parse2};

use crate::attrs;

/// Declares a serde DTO: derives `Tsify` under the `wasm` feature and opts the type into both ABI
/// directions.
pub(crate) fn wasm_record(attr: TokenStream, item: TokenStream) -> TokenStream {
    if !attr.is_empty() {
        return syn::Error::new_spanned(attr, "#[wasm_record] takes no arguments")
            .to_compile_error();
    }

    let item = match parse2::<Item>(item) {
        Ok(item) => item,
        Err(err) => return err.to_compile_error(),
    };

    if let Err(err) = attrs::check_exportable_type(&item, "wasm_record") {
        return err.to_compile_error();
    }

    // `#[serde(..)]` and `#[tsify(..)]` stay on the item and its fields for `Tsify`'s derive to
    // read, so the item is emitted as written.
    let item = item.to_token_stream();
    quote! {
        #[cfg_attr(
            feature = "wasm",
            derive(::bitwarden_ffi::_macro::Tsify),
            tsify(into_wasm_abi, from_wasm_abi)
        )]
        #item
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expand(item: TokenStream) -> String {
        wasm_record(TokenStream::new(), item)
            .to_string()
            .replace(' ', "")
    }

    #[test]
    fn derives_tsify_for_both_abi_directions() {
        let out = expand(quote! {
            #[derive(Serialize, Deserialize)]
            pub struct Point { pub x: i32 }
        });

        assert!(!out.contains("compile_error!"), "{out}");
        assert!(
            out.contains("derive(::bitwarden_ffi::_macro::Tsify)"),
            "{out}"
        );
        assert!(out.contains("tsify(into_wasm_abi,from_wasm_abi)"), "{out}");
        assert!(out.contains("feature=\"wasm\""), "{out}");
    }

    #[test]
    fn leaves_tsify_and_serde_attributes_in_place() {
        // `Tsify`'s derive reads both, so neither may be consumed here.
        let out = expand(quote! {
            #[derive(Serialize, Deserialize)]
            #[serde(rename_all = "camelCase")]
            pub struct Cipher {
                #[cfg_attr(feature = "wasm", tsify(optional))]
                pub name: Option<String>,
            }
        });

        assert!(out.contains("#[serde(rename_all=\"camelCase\")]"), "{out}");
        assert!(
            out.contains("#[cfg_attr(feature=\"wasm\",tsify(optional))]"),
            "{out}"
        );
    }

    #[test]
    fn rejects_arguments() {
        let out = wasm_record(quote!(into_wasm_abi), quote! { pub struct Point; })
            .to_string()
            .replace(' ', "");

        assert!(out.contains("compile_error!"), "{out}");
        assert!(out.contains("takesnoarguments"), "{out}");
    }

    #[test]
    fn rejects_generics() {
        let out = expand(quote! {
            pub struct Wrapper<T> { pub inner: T }
        });

        assert!(out.contains("compile_error!"), "{out}");
        assert!(out.contains("doesnotsupportgenerics"), "{out}");
    }

    #[test]
    fn rejects_an_item_that_is_not_a_struct_or_an_enum() {
        let out = expand(quote! {
            pub fn point() {}
        });

        assert!(out.contains("compile_error!"), "{out}");
        assert!(out.contains("appliestoastructoranenum"), "{out}");
    }
}
