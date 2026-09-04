use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::{Item, parse2};

/// Declares a serde DTO: derives `Tsify` under the `wasm` feature and implements the wire traits so
/// it crosses as `Ts<Self>`.
pub(crate) fn wasm_record(attr: TokenStream, item: TokenStream) -> TokenStream {
    if !attr.is_empty() {
        return syn::Error::new_spanned(attr, "#[wasm_record] takes no arguments")
            .to_compile_error();
    }

    let item = match parse2::<Item>(item) {
        Ok(item) => item,
        Err(err) => return err.to_compile_error(),
    };

    // `#[tsify(..)]` and serde attributes stay on the item for `Tsify`'s derive to read.
    let ident = match &item {
        Item::Struct(s) => &s.ident,
        Item::Enum(e) => &e.ident,
        other => {
            return syn::Error::new_spanned(other, "#[wasm_record] applies to a struct or an enum")
                .to_compile_error();
        }
    };

    let generics = match &item {
        Item::Struct(s) => &s.generics,
        Item::Enum(e) => &e.generics,
        _ => unreachable!("checked above"),
    };
    if !generics.params.is_empty() {
        return syn::Error::new_spanned(
            generics,
            "#[wasm_record] does not support generics; wasm_bindgen cannot export generic types",
        )
        .to_compile_error();
    }

    let item = item.to_token_stream();
    quote! {
        #[cfg_attr(feature = "wasm", derive(::tsify::Tsify))]
        #item

        #[cfg(feature = "wasm")]
        ::bitwarden_ffi::impl_wire_record!(#ident);
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
    fn derives_tsify_and_implements_the_wire_traits() {
        let out = expand(quote! {
            #[derive(Serialize, Deserialize)]
            pub struct Point { pub x: i32 }
        });

        assert!(!out.contains("compile_error!"), "{out}");
        assert!(out.contains("derive(::tsify::Tsify)"), "{out}");
        assert!(out.contains("impl_wire_record!(Point)"), "{out}");
    }

    #[test]
    fn leaves_tsify_and_serde_attributes_in_place() {
        // `Tsify`'s derive reads both, so neither may be consumed here.
        let out = expand(quote! {
            #[derive(Serialize, Deserialize)]
            #[serde(rename_all = "camelCase")]
            #[tsify(namespace)]
            pub enum Kind { A, B }
        });

        assert!(out.contains("#[serde(rename_all=\"camelCase\")]"), "{out}");
        assert!(out.contains("#[tsify(namespace)]"), "{out}");
        assert!(out.contains("impl_wire_record!(Kind)"), "{out}");
    }

    #[test]
    fn rejects_generics() {
        let out = expand(quote! {
            pub struct Wrapper<T> { pub inner: T }
        });

        assert!(out.contains("compile_error!"), "{out}");
        assert!(out.contains("doesnotsupportgenerics"), "{out}");
    }
}
