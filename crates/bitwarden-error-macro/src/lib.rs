mod metadata;

use quote::quote;
use syn::Data;

#[proc_macro_attribute]
pub fn bitwarden_error(
    _args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(item as syn::DeriveInput);

    quote! {
        #[derive(ErrorVariant)]
        #input
    }
    .into()
}

#[proc_macro_derive(ErrorVariant)]
pub fn error_variant(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(item as syn::DeriveInput);
    let type_identifier = &input.ident;

    match &input.data {
        Data::Enum(data) => {
            let match_arms = data.variants.iter().map(|variant| match variant.fields {
                syn::Fields::Unit => {
                    let variant_ident = &variant.ident;
                    let variant_name = format!("{}::{}", type_identifier, variant_ident);
                    quote! {
                        #type_identifier::#variant_ident => #variant_name
                    }
                }
                syn::Fields::Named(_) => {
                    let variant_ident = &variant.ident;
                    let variant_name = format!("{}::{}", type_identifier, variant_ident);
                    quote! {
                        #type_identifier::#variant_ident { .. } => #variant_name
                    }
                }
                syn::Fields::Unnamed(_) => {
                    let variant_ident = &variant.ident;
                    let variant_name = format!("{}::{}", type_identifier, variant_ident);
                    quote! {
                        #type_identifier::#variant_ident(..) => #variant_name
                    }
                }
            });

            quote! {
                #[automatically_derived]
                impl ErrorVariant for #type_identifier {
                    fn error_variant(&self) -> &'static str {
                        match &self {
                            #(#match_arms), *
                        }
                    }
                }
            }
            .into()
        }
        Data::Struct(_) => {
            let type_identifier = &input.ident;
            let variant_name = format!("{}", type_identifier);

            quote! {
                #[automatically_derived]
                impl ErrorVariant for #type_identifier {
                    fn error_variant(&self) -> &'static str {
                        #variant_name
                    }
                }
            }
            .into()
        }
        Data::Union(_) => {
            syn::Error::new_spanned(input, "bitwarden_error cannot be used with unions")
                .to_compile_error()
                .into()
        }
    }
}
