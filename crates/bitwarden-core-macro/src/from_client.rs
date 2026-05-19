//! Expansion logic for `#[derive(FromClient)]`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::DeriveInput;

/// Generates `impl FromClient for #StructName { fn from_client(client: &Client) -> Self { ... } }`
/// by extracting each named field from the `Client` via `FromClientPart::get_part`.
pub(crate) fn expand(input: DeriveInput) -> TokenStream {
    let struct_name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let syn::Data::Struct(syn::DataStruct {
        fields: syn::Fields::Named(fields),
        ..
    }) = &input.data
    else {
        return syn::Error::new_spanned(
            &input,
            "FromClient can only be derived for structs with named fields",
        )
        .to_compile_error();
    };

    let field_inits = fields.named.iter().filter_map(|f| {
        let field_name = f.ident.as_ref()?;
        let field_type = &f.ty;
        Some(quote! {
            #field_name: ::bitwarden_core::client::FromClientPart::<#field_type>::get_part(client)
        })
    });

    quote! {
        impl #impl_generics ::bitwarden_core::client::FromClient for #struct_name #ty_generics #where_clause {
            fn from_client(client: &::bitwarden_core::Client) -> Self {
                Self {
                    #(#field_inits),*
                }
            }
        }
    }
}
