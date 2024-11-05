mod metadata;

use quote::quote;
use syn::Data;

#[proc_macro_attribute]
pub fn bitwarden_error(
    _args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    item
}

#[proc_macro_derive(AsErrorMetadata)]
pub fn as_error_metadata(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(item as syn::DeriveInput);
    let struct_identifier = &input.ident;

    // let mut implementation = {quote, format_ident}!{
    //     match &self {
    //     };
    // };

    match &input.data {
        Data::Enum(data) => {
            let field_identifiers = data
                .variants
                .iter()
                .map(|item| item.ident.clone())
                .collect::<Vec<_>>();

            let variant_names: Vec<_> = field_identifiers
                .iter()
                .map(|ident| format!("{}::{}", struct_identifier, ident))
                .collect();

            quote! {
                #[automatically_derived]
                impl AsErrorMetadata for #struct_identifier {
                    fn as_metadata(&self) -> ErrorMetadata {
                        match &self {
                            #(
                                #struct_identifier::#field_identifiers => ErrorMetadata {
                                    name: #variant_names,
                                    message: concat!("An error occurred in the ", stringify!(#field_identifiers), " variant"),
                                },
                            )*
                        }
                    }
                }
            }
            .into()
        }
        _ => unimplemented!(),
    }
}
