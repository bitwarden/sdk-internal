#![doc = include_str!("../README.md")]

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    Ident, Visibility,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

#[allow(missing_docs)]
#[proc_macro]
pub fn uuid_newtype(input: TokenStream) -> TokenStream {
    // Parse input as: vis ident
    let input = parse_macro_input!(input as IdTypeInput);
    let ident = input.ident;
    let vis = input.vis;
    let name_str = ident.to_string();

    let tsify_type = format!("Tagged<Uuid, \"{name_str}\">");
    let doc_string = format!(" NewType wrapper for `{name_str}`");

    let expanded = quote! {
        #[doc = #doc_string]
        #[cfg_attr(feature = "wasm", derive(::tsify::Tsify), tsify(into_wasm_abi, from_wasm_abi))]
        #[derive(
            ::serde::Serialize, ::serde::Deserialize,
            ::std::cmp::PartialEq, ::std::cmp::Eq, ::std::cmp::PartialOrd, ::std::cmp::Ord,
            ::std::hash::Hash, ::std::clone::Clone, ::std::marker::Copy, ::std::fmt::Debug
        )]
        #[repr(transparent)]
        #vis struct #ident
        (
            #[cfg_attr(feature = "wasm", tsify(type = #tsify_type))]
            ::uuid::Uuid
        );

        #[cfg(feature = "uniffi")]
        uniffi::custom_newtype!(#ident, uuid::Uuid);

        impl #ident {
            #[allow(missing_docs)]
            pub fn new(value: uuid::Uuid) -> Self {
                Self(value)
            }

            /// Create a new UUID v4 based id.
            pub fn new_v4() -> Self {
                Self(uuid::Uuid::new_v4())
            }
        }

        impl ::std::str::FromStr for #ident {
            type Err = uuid::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                uuid::Uuid::from_str(s).map(Self)
            }
        }

        impl From<#ident> for ::uuid::Uuid {
            fn from(value: #ident) -> Self {
                value.0
            }
        }

        impl ::std::fmt::Display for #ident {
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl ::std::default::Default for #ident {
            fn default() -> Self {
                Self(uuid::Uuid::default())
            }
        }
    };

    TokenStream::from(expanded)
}

// Helper struct to parse "vis ident"
struct IdTypeInput {
    vis: Visibility,
    ident: Ident,
}

impl Parse for IdTypeInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let vis: Visibility = input.parse()?;
        let ident: Ident = input.parse()?;
        Ok(IdTypeInput { vis, ident })
    }
}
