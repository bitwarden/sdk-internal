use quote::quote;

pub(crate) fn bitwarden_error_full(input: &syn::DeriveInput) -> proc_macro::TokenStream {
    let wasm_attributes = cfg!(feature = "wasm").then(|| {
        quote! {
            #[derive(tsify_next::Tsify)]
            #[tsify(into_wasm_abi)]
        }
    });

    quote! {
        #[derive(serde::Serialize)]
        #wasm_attributes
        #input
    }
    .into()
}
