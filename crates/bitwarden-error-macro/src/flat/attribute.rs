use quote::quote;

pub(crate) fn bitwarden_error_flat(input: &syn::DeriveInput) -> proc_macro::TokenStream {
    quote! {
        #[derive(FlatError)]
        #input
    }
    .into()
}
