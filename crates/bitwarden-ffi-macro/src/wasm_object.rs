use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::{Item, Meta, Token, parse::Parser, parse2, punctuated::Punctuated};

/// Declares a `#[wasm_bindgen]` handle type: applies `#[wasm_bindgen]` under the `wasm` feature and
/// implements the wire traits so it crosses as itself rather than through serde.
///
/// Arguments are forwarded to `#[wasm_bindgen]`, so `#[wasm_object(js_name = Foo)]` behaves as it
/// would there.
pub(crate) fn wasm_object(attr: TokenStream, item: TokenStream) -> TokenStream {
    let forwarded = if attr.is_empty() {
        Punctuated::<Meta, Token![,]>::new()
    } else {
        match Punctuated::<Meta, Token![,]>::parse_terminated.parse2(attr) {
            Ok(args) => args,
            Err(err) => return err.to_compile_error(),
        }
    };

    let item = match parse2::<Item>(item) {
        Ok(item) => item,
        Err(err) => return err.to_compile_error(),
    };

    let (ident, generics) = match &item {
        Item::Struct(s) => (&s.ident, &s.generics),
        Item::Enum(e) => (&e.ident, &e.generics),
        other => {
            return syn::Error::new_spanned(other, "#[wasm_object] applies to a struct or an enum")
                .to_compile_error();
        }
    };

    if !generics.params.is_empty() {
        return syn::Error::new_spanned(
            generics,
            "#[wasm_object] does not support generics; wasm_bindgen cannot export generic types",
        )
        .to_compile_error();
    }

    let bindgen = if forwarded.is_empty() {
        quote!(wasm_bindgen)
    } else {
        quote!(wasm_bindgen(#forwarded))
    };

    let item = item.to_token_stream();
    quote! {
        #[cfg_attr(feature = "wasm", ::wasm_bindgen::prelude::#bindgen)]
        #item

        #[cfg(feature = "wasm")]
        ::bitwarden_ffi::impl_wire_object!(#ident);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expand(attr: TokenStream, item: TokenStream) -> String {
        wasm_object(attr, item).to_string().replace(' ', "")
    }

    #[test]
    fn applies_wasm_bindgen_and_implements_the_wire_traits() {
        let out = expand(
            TokenStream::new(),
            quote! {
                pub struct CiphersClient { client: Client }
            },
        );

        assert!(!out.contains("compile_error!"), "{out}");
        assert!(
            out.contains("::wasm_bindgen::prelude::wasm_bindgen"),
            "{out}"
        );
        assert!(out.contains("impl_wire_object!(CiphersClient)"), "{out}");
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
            out.contains("::wasm_bindgen::prelude::wasm_bindgen(js_name=Ciphers)"),
            "{out}"
        );
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
