use quote::quote;

pub(crate) fn bitwarden_error_flat(input: &syn::DeriveInput) -> proc_macro::TokenStream {
    let type_identifier = &input.ident;

    quote! {
        #[derive(FlatError)]
        #input

        impl BitwardenError for #type_identifier {}
    }
    .into()
}
