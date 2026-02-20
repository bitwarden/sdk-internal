//! Proc macros for the Bitwarden SDK.
//!
//! Provides:
//! - `#[derive(FromClient)]` derive macro for implementing the `FromClient` trait on client
//!   structs.

use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, parse_macro_input};

/// Derive macro for implementing the `FromClient` trait on client structs.
///
/// This macro generates an implementation of the `FromClient` trait that extracts
/// all struct fields from a `Client` using the `FromClientPart` trait.
///
/// # Example
///
/// ```ignore
/// use bitwarden_core::client::FromClient;
/// use bitwarden_core_macro::FromClient;
///
/// #[derive(FromClient)]
/// pub struct FoldersClient {
///     key_store: KeyStore<KeyIds>,
///     api_config_provider: Arc<dyn ApiProvider>,
///     repository: Arc<dyn Repository<Folder>>,
/// }
/// ```
///
/// The macro generates:
///
/// ```ignore
/// impl FromClient for FoldersClient {
///     fn from_client(client: &Client) -> Result<Self, String> {
///         Ok(Self {
///             key_store: FromClientPart::<KeyStore<KeyIds>>::get_part(client).map_err(|e| e.to_string())?,
///             api_config_provider: FromClientPart::<Arc<dyn ApiProvider>>::get_part(client).map_err(|e| e.to_string())?,
///             repository: FromClientPart::<Arc<dyn Repository<Folder>>>::get_part(client).map_err(|e| e.to_string())?,
///         })
///     }
/// }
/// ```
#[proc_macro_derive(FromClient)]
pub fn derive_from_client(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);

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
        .to_compile_error()
        .into();
    };

    let field_inits = fields.named.iter().filter_map(|f| {
        let field_name = f.ident.as_ref()?;
        let field_type = &f.ty;
        Some(quote! {
            #field_name: ::bitwarden_core::client::FromClientPart::<#field_type>::get_part(client).map_err(|e| e.to_string())?
        })
    });

    let expanded = quote! {
        impl #impl_generics ::bitwarden_core::client::FromClient for #struct_name #ty_generics #where_clause {
            fn from_client(client: &::bitwarden_core::Client) -> Result<Self, String> {
                Ok(Self {
                    #(#field_inits),*
                })
            }
        }
    };

    TokenStream::from(expanded)
}
