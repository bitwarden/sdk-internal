use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::{Item, parse2};

use crate::attrs;

/// Declares a `#[wasm_bindgen]` handle type, forwarding this macro's arguments to it.
pub(crate) fn wasm_object(attr: TokenStream, item: TokenStream) -> TokenStream {
    let forwarded = match attrs::parse_args(attr) {
        Ok(args) => args,
        Err(err) => return err.to_compile_error(),
    };

    let item = match parse2::<Item>(item) {
        Ok(item) => item,
        Err(err) => return err.to_compile_error(),
    };

    if let Err(err) = attrs::check_exportable_type(&item, "wasm_object") {
        return err.to_compile_error();
    }

    let bindgen = attrs::wasm_bindgen_attr(&forwarded);
    let item = item.to_token_stream();
    quote! {
        #bindgen
        #item
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expand(attr: TokenStream, item: TokenStream) -> String {
        wasm_object(attr, item).to_string().replace(' ', "")
    }

    #[test]
    fn applies_wasm_bindgen_under_the_wasm_feature() {
        let out = expand(
            TokenStream::new(),
            quote! {
                pub struct CiphersClient { client: Client }
            },
        );

        assert!(!out.contains("compile_error!"), "{out}");
        assert!(
            out.contains("#[cfg_attr(feature=\"wasm\",::bitwarden_ffi::_macro::wasm_bindgen)]"),
            "{out}"
        );
    }

    #[test]
    fn forwards_its_arguments_to_wasm_bindgen() {
        let out = expand(
            quote!(js_name = Ciphers),
            quote! {
                pub struct CiphersClient;
            },
        );

        assert!(
            out.contains("::bitwarden_ffi::_macro::wasm_bindgen(js_name=Ciphers)"),
            "{out}"
        );
    }

    #[test]
    fn leaves_field_attributes_in_place() {
        let out = expand(
            TokenStream::new(),
            quote! {
                pub struct JsIpcClient {
                    #[wasm_bindgen(skip)]
                    pub client: Arc<dyn IpcClient>,
                }
            },
        );

        assert!(out.contains("#[wasm_bindgen(skip)]"), "{out}");
    }

    #[test]
    fn rejects_an_unparseable_argument_list() {
        let out = expand(quote!(js_name =), quote! { pub struct CiphersClient; });

        assert!(out.contains("compile_error!"), "{out}");
    }

    #[test]
    fn rejects_generics() {
        let out = expand(
            TokenStream::new(),
            quote! {
                pub struct Holder<T> { inner: T }
            },
        );

        assert!(out.contains("compile_error!"), "{out}");
        assert!(out.contains("doesnotsupportgenerics"), "{out}");
    }
}
