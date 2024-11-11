use quote::quote;

pub(crate) fn bitwarden_error_basic(input: &syn::DeriveInput) -> proc_macro::TokenStream {
    quote! {
        #[derive(BasicError)]
        #input
    }
    .into()
}
