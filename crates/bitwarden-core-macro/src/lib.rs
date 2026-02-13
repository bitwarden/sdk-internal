//! Proc macros for the Bitwarden SDK.
//!
//! Provides:
//! - `#[from_client]` attribute macro for generating `from_client` methods on client structs.

use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemStruct, parse_macro_input};

/// Attribute macro for generating `from_client` methods on client structs.
///
/// This macro generates a `from_client` method that extracts all struct fields from a
/// `Client` using the `FromClientPart` trait.
///
/// # Example
///
/// ```ignore
/// use bitwarden_core_macro::from_client;
///
/// #[from_client]
/// pub struct FoldersClient {
///     key_store: KeyStore<KeyIds>,
///     api_config_provider: Arc<dyn ApiProvider>,
///     repository: Arc<dyn Repository<Folder>>,
/// }
/// ```
///
/// The macro transforms the above into:
///
/// ```ignore
/// pub struct FoldersClient {
///     key_store: KeyStore<KeyIds>,
///     api_config_provider: Arc<dyn ApiProvider>,
///     repository: Arc<dyn Repository<Folder>>,
/// }
///
/// impl FoldersClient {
///     pub(crate) fn from_client(client: &Client) -> Result<Self, String> {
///         Ok(Self {
///             key_store: client.from_client_part().map_err(|e| e.to_string())?,
///             api_config_provider: client.from_client_part().map_err(|e| e.to_string())?,
///             repository: client.from_client_part().map_err(|e| e.to_string())?,
///         })
///     }
/// }
/// ```
#[proc_macro_attribute]
pub fn from_client(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemStruct);

    let struct_name = &input.ident;
    let struct_vis = &input.vis;
    let struct_attrs = &input.attrs;
    let struct_generics = &input.generics;
    let struct_fields = &input.fields;

    // Generate field initialization for each named field
    let field_inits = struct_fields.iter().filter_map(|f| {
        let field_name = f.ident.as_ref()?;
        let field_type = &f.ty;
        Some(quote! {
            #field_name: <_ as ::bitwarden_core::client::FromClientPart<#field_type>>::from_client_part(client).map_err(|e| e.to_string())?
        })
    });

    let expanded = quote! {
        #(#struct_attrs)*
        #struct_vis struct #struct_name #struct_generics #struct_fields

        impl #struct_generics #struct_name #struct_generics {
            pub(crate) fn from_client(
                client: &::bitwarden_core::Client
            ) -> Result<Self, String> {
                Ok(Self {
                    #(#field_inits),*
                })
            }
        }
    };

    TokenStream::from(expanded)
}
