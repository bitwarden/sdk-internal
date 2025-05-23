use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input, Ident, Visibility,
};

#[proc_macro]
pub fn uuid(input: TokenStream) -> TokenStream {
    // Parse input as: vis ident
    let input = parse_macro_input!(input as IdTypeInput);
    let ident = input.ident;
    let vis = input.vis;
    let name_str = ident.to_string();

    let tsify_type = format!("Tagged<Uuid, \"{}\">", name_str);

    let expanded = quote! {
        #[cfg(feature = "wasm")]
        #[derive(serde::Serialize, serde::Deserialize, tsify_next::Tsify)]
        #[tsify(into_wasm_abi, from_wasm_abi)]
        #[repr(transparent)]
        #vis struct #ident(
            #[tsify(type = #tsify_type)]
            pub uuid::Uuid
        );

        #[cfg(not(feature = "wasm"))]
        #[derive(serde::Serialize, serde::Deserialize)]
        #[repr(transparent)]
        #vis struct #ident(
            pub uuid::Uuid
        );

        #[cfg(feature = "uniffi")]
        uniffi::custom_newtype!(#ident, uuid::Uuid);
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
