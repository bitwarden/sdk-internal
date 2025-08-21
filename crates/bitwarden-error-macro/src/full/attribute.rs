use darling::Error;
use quote::quote;

pub(crate) fn bitwarden_error_full(
    input: &syn::DeriveInput,
    type_identifier: &proc_macro2::Ident,
    export_as_identifier: &proc_macro2::Ident,
) -> proc_macro::TokenStream {
    if type_identifier != export_as_identifier {
        return Error::custom("`bitwarden_error(full)` does not currently support `export_as`")
            .write_errors()
            .into();
    }

    let wasm_attributes = cfg!(feature = "wasm").then(|| {
        quote! {
            #[derive(bitwarden_error::tsify::Tsify)]
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
