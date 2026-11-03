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

    quote! {
        #[derive(serde::Serialize)]
        #[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
        #[cfg_attr(feature = "wasm", derive(bitwarden_error::tsify::Tsify), tsify(into_wasm_abi))]
        #input
    }
    .into()
}
