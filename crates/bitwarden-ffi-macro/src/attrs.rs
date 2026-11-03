use proc_macro2::TokenStream;
use quote::quote;
use syn::{Attribute, Item, Meta, Token, parse::Parser, punctuated::Punctuated};

/// The arguments of an attribute, as written between its parentheses.
pub(crate) type Args = Punctuated<Meta, Token![,]>;

/// Parses a macro's own arguments, all of which are forwarded to the attribute it stands in for.
pub(crate) fn parse_args(attr: TokenStream) -> syn::Result<Args> {
    if attr.is_empty() {
        return Ok(Args::new());
    }
    Args::parse_terminated.parse2(attr)
}

/// `#[cfg_attr(feature = "wasm", wasm_bindgen(<args>))]`, named through `bitwarden_ffi` so a call
/// site imports nothing.
pub(crate) fn wasm_bindgen_attr(args: &Args) -> TokenStream {
    let call = if args.is_empty() {
        quote!(wasm_bindgen)
    } else {
        quote!(wasm_bindgen(#args))
    };
    quote!(#[cfg_attr(feature = "wasm", ::bitwarden_ffi::_macro::#call)])
}

/// The `wasm_bindgen(..)` arguments an attribute carries, whether written plainly or under
/// `#[cfg_attr(feature = "wasm", ..)]`.
pub(crate) fn wasm_bindgen_args(attr: &Attribute) -> Option<Args> {
    let inner = if attr.path().is_ident("wasm_bindgen") {
        attr.meta.clone()
    } else if attr.path().is_ident("cfg_attr") {
        let Meta::List(list) = &attr.meta else {
            return None;
        };
        list.parse_args_with(Args::parse_terminated)
            .ok()?
            .into_iter()
            .find(|meta| meta.path().is_ident("wasm_bindgen"))?
    } else {
        return None;
    };

    Some(match inner {
        Meta::List(list) => list.parse_args_with(Args::parse_terminated).ok()?,
        _ => Args::new(),
    })
}

/// The `#[wasm_bindgen]` an item already carries, which a macro standing in for one must reject.
pub(crate) fn find_wasm_bindgen(attrs: &[Attribute]) -> Option<&Attribute> {
    attrs.iter().find(|attr| wasm_bindgen_args(attr).is_some())
}

/// Rejects an item `#[wasm_bindgen]` cannot export: anything that is not a struct or an enum, and
/// any generic parameters on one.
pub(crate) fn check_exportable_type(item: &Item, macro_name: &str) -> syn::Result<()> {
    let generics = match item {
        Item::Struct(item) => &item.generics,
        Item::Enum(item) => &item.generics,
        other => {
            return Err(syn::Error::new_spanned(
                other,
                format!("#[{macro_name}] applies to a struct or an enum"),
            ));
        }
    };

    if !generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            generics,
            format!(
                "#[{macro_name}] does not support generics; wasm_bindgen cannot export generic types"
            ),
        ));
    }

    Ok(())
}
