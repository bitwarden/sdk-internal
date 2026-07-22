//! Proc macros for the Bitwarden SDK.
//!
//! Provides:
//! - `#[derive(FromClient)]` derive macro for implementing the `FromClient` trait on client
//!   structs.
//! - `#[client_trait]` attribute macro that generates a `FromClientShared` bridge for a feature
//!   client's hand-written trait.

use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, Expr, ItemTrait, parse::Parser, parse_macro_input};

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
///     key_store: KeyStore<KeySlotIds>,
///     api_configurations: Arc<ApiConfigurations>,
///     repository: Option<Arc<dyn Repository<Folder>>>,
/// }
/// ```
///
/// The macro generates:
///
/// ```ignore
/// impl FromClient for FoldersClient {
///     fn from_client(client: &Client) -> Self {
///         Self {
///             key_store: FromClientPart::<KeyStore<KeySlotIds>>::get_part(client),
///             api_configs: FromClientPart::<Arc<ApiConfigurations>>::get_part(client),
///             repository: FromClientPart::<Option<Arc<dyn Repository<Folder>>>>::get_part(client),
///         }
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
            #field_name: ::bitwarden_core::client::FromClientPart::<#field_type>::get_part(client)
        })
    });

    let expanded = quote! {
        impl #impl_generics ::bitwarden_core::client::FromClient for #struct_name #ty_generics #where_clause {
            fn from_client(client: &::bitwarden_core::Client) -> Self {
                Self {
                    #(#field_inits),*
                }
            }
        }
    };

    TokenStream::from(expanded)
}

/// Attribute macro that emits the `FromClientShared` bridge for a hand-written feature client
/// trait.
///
/// Applied to a `trait FooTrait { ... }` declaration with a `via = <expression>` argument, it
/// re-emits the trait unchanged and adds:
///
/// ```ignore
/// impl FromClientShared for dyn FooTrait {
///     fn from_client_shared(client: &Client) -> Arc<Self> {
///         Arc::new(<expression>)
///     }
/// }
/// ```
///
/// The expression has `client: &Client` in scope and must evaluate to a value that can be
/// wrapped in `Arc<dyn FooTrait>` (typically a concrete struct that implements the trait).
///
/// # Example
///
/// ```ignore
/// #[client_trait(via = client.folders())]
/// #[cfg_attr(any(test, feature = "test-fixtures"), mockall::automock)]
/// #[async_trait::async_trait]
/// pub trait FoldersClientTrait: Send + Sync {
///     async fn get(&self, id: FolderId) -> Result<FolderView, FolderError>;
/// }
/// ```
#[proc_macro_attribute]
pub fn client_trait(args: TokenStream, item: TokenStream) -> TokenStream {
    let mut via_expr: Option<Expr> = None;
    let parser = syn::meta::parser(|meta| {
        if meta.path.is_ident("via") {
            via_expr = Some(meta.value()?.parse::<Expr>()?);
            Ok(())
        } else {
            Err(meta.error("expected `via = <expression>`"))
        }
    });

    if let Err(e) = parser.parse(args) {
        return e.to_compile_error().into();
    }

    let item_trait = parse_macro_input!(item as ItemTrait);
    let Some(via_expr) = via_expr else {
        return syn::Error::new_spanned(
            &item_trait.ident,
            "#[client_trait] requires a `via = <expression>` argument",
        )
        .to_compile_error()
        .into();
    };

    let trait_ident = &item_trait.ident;
    let expanded = quote! {
        #item_trait

        impl ::bitwarden_core::client::FromClientShared for dyn #trait_ident {
            fn from_client_shared(
                client: &::bitwarden_core::Client,
            ) -> ::std::sync::Arc<Self> {
                ::std::sync::Arc::new(#via_expr)
            }
        }
    };
    expanded.into()
}
