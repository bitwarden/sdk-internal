use quote::quote;

pub(crate) fn bitwarden_error_full(
    input: &syn::DeriveInput,
    _type_identifier: &proc_macro2::Ident,
    _export_as_identifier: &proc_macro2::Ident,
) -> proc_macro::TokenStream {
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
