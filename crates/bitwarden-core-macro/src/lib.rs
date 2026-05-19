//! Proc macros for the Bitwarden SDK.
//!
//! Provides:
//! - `#[derive(FromClient)]` derive macro for implementing the `FromClient` trait on client
//!   structs.
//! - `#[client_trait]` attribute macro for generating a mockable trait alongside a feature client's
//!   inherent impl block.

use proc_macro::TokenStream;
use syn::{DeriveInput, Expr, ItemImpl, parse::Parser, parse_macro_input};

mod client_trait;
mod from_client;

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
    from_client::expand(input).into()
}

/// Attribute macro for generating a mockable trait alongside a feature client's inherent impl.
///
/// Applied to an inherent `impl Foo { ... }` block, this macro generates a public trait
/// `FooTrait` mirroring the `pub` methods, plus a forwarding `impl FooTrait for Foo`. The
/// original `impl` block is re-emitted unchanged, so existing call sites keep working.
///
/// When `cfg(test)` or `feature = "test-fixtures"` is active, the generated trait is decorated
/// with `#[mockall::automock]`, giving consumers a free `MockFooTrait` for unit tests.
///
/// # Auto-bridging into `FromClient`
///
/// Pass `via = <expression>` to also emit `impl FromClientShared for dyn FooTrait`, so a
/// struct deriving [`FromClient`] can hold an `Arc<dyn FooTrait>` field and have it
/// constructed automatically. The expression is evaluated with `client: &Client` in scope and
/// must produce `Self`:
///
/// ```ignore
/// #[client_trait(via = client.sync())]            // extension method (idiomatic)
/// #[client_trait(via = SyncClient::new(client.clone()))]   // free constructor
/// #[client_trait(via = Self::from_client(client))]         // FromClient if you want it
/// ```
///
/// When `via` is omitted, no `FromClientShared` impl is generated - you get only the trait,
/// forwarding impl, and mock.
///
/// # Example
///
/// ```ignore
/// use bitwarden_core_macro::client_trait;
///
/// #[client_trait(via = client.folders())]
/// impl FoldersClient {
///     pub async fn get(&self, id: FolderId) -> Result<FolderView, FolderError> { /* ... */ }
///     pub fn count(&self) -> usize { /* ... */ }
///
///     // Methods without `pub` are not included in the trait.
///     fn internal_helper(&self) { /* ... */ }
///
///     // Use `#[client_trait(skip)]` to opt out of a specific public method.
///     #[client_trait(skip)]
///     pub fn weird<T: SomeBound>(&self, t: T) { /* ... */ }
/// }
/// ```
///
/// The generated trait has bounds `Send + Sync` so dependents can hold the client as
/// `Arc<dyn FoldersClientTrait>` across threads.
#[proc_macro_attribute]
pub fn client_trait(args: TokenStream, item: TokenStream) -> TokenStream {
    let mut via_expr: Option<Expr> = None;
    let parser = syn::meta::parser(|meta| {
        if meta.path.is_ident("via") {
            via_expr = Some(meta.value()?.parse::<Expr>()?);
            Ok(())
        } else {
            Err(meta.error(format!(
                "unknown #[client_trait] argument `{}`; expected `via = <expression>`",
                meta.path
                    .get_ident()
                    .map(|i| i.to_string())
                    .unwrap_or_else(|| "<path>".to_string())
            )))
        }
    });

    if let Err(e) = parser.parse(args) {
        return e.to_compile_error().into();
    }

    let item_impl = parse_macro_input!(item as ItemImpl);
    match client_trait::expand(item_impl, via_expr) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}
