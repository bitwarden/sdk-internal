//! Proc macros for the Bitwarden SDK.
//!
//! Provides:
//! - `#[derive(FromClient)]` derive macro for implementing the `FromClient` trait on client
//!   structs.
//! - `#[client_trait]` attribute macro for generating a mockable trait alongside a feature client's
//!   inherent impl block.

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    DeriveInput, Error, FnArg, ImplItem, ItemImpl, Type, Visibility, parse_macro_input,
    spanned::Spanned,
};

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

/// Attribute macro for generating a mockable trait alongside a feature client's inherent impl.
///
/// Applied to an inherent `impl Foo { ... }` block, this macro generates a public trait
/// `FooTrait` mirroring the `pub` methods, plus a forwarding `impl FooTrait for Foo`. The
/// original `impl` block is re-emitted unchanged, so existing call sites keep working.
///
/// When `cfg(test)` or `feature = "test-fixtures"` is active, the generated trait is decorated
/// with `#[mockall::automock]`, giving consumers a free `MockFooTrait` for unit tests.
///
/// # Example
///
/// ```ignore
/// use bitwarden_core_macro::client_trait;
///
/// #[client_trait]
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
    // No attribute arguments are supported at the moment; future extensions could include
    // `#[client_trait(name = "CustomTrait")]` for overriding the generated trait name.
    if !args.is_empty() {
        return Error::new(
            proc_macro2::TokenStream::from(args).span(),
            "#[client_trait] does not accept arguments yet",
        )
        .to_compile_error()
        .into();
    }

    let item_impl = parse_macro_input!(item as ItemImpl);
    match expand_client_trait(item_impl) {
        Ok(ts) => ts.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

fn expand_client_trait(mut item_impl: ItemImpl) -> Result<proc_macro2::TokenStream, Error> {
    if let Some((_, path, _)) = &item_impl.trait_ {
        return Err(Error::new_spanned(
            path,
            "#[client_trait] must be placed on an inherent impl block, not a trait impl",
        ));
    }

    if !item_impl.generics.params.is_empty() {
        return Err(Error::new_spanned(
            &item_impl.generics,
            "#[client_trait] does not support generic impl blocks yet",
        ));
    }

    let struct_ident = match &*item_impl.self_ty {
        Type::Path(tp) if tp.qself.is_none() => match tp.path.segments.last() {
            Some(seg) if seg.arguments.is_empty() => seg.ident.clone(),
            _ => {
                return Err(Error::new_spanned(
                    &item_impl.self_ty,
                    "#[client_trait] requires a simple path type like `FoldersClient`",
                ));
            }
        },
        _ => {
            return Err(Error::new_spanned(
                &item_impl.self_ty,
                "#[client_trait] requires the impl to target a named type",
            ));
        }
    };

    let trait_ident = format_ident!("{}Trait", struct_ident);

    let mut trait_methods = Vec::new();
    let mut impl_methods = Vec::new();
    let mut any_async = false;

    for item in &item_impl.items {
        let ImplItem::Fn(method) = item else {
            // Pass through associated consts / types / etc. unchanged - they stay on the
            // inherent impl only.
            continue;
        };

        if !matches!(method.vis, Visibility::Public(_)) {
            continue;
        }

        // Allow opting a method out via `#[client_trait(skip)]`.
        let skip = method.attrs.iter().any(|attr| {
            if !attr.path().is_ident("client_trait") {
                return false;
            }
            let mut found_skip = false;
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("skip") {
                    found_skip = true;
                }
                Ok(())
            });
            found_skip
        });
        if skip {
            continue;
        }

        let sig = &method.sig;
        if sig.asyncness.is_some() {
            any_async = true;
        }

        // Methods that consume `self` (no receiver, or `self: Self`) can't be called through
        // `dyn Trait`; skip them rather than generating a broken trait.
        let Some(FnArg::Receiver(_recv)) = sig.inputs.first() else {
            continue;
        };

        // Forward inherent attributes that should travel with the method onto the trait method
        // (and the forwarding impl). `#[client_trait(...)]` is consumed; everything else
        // (doc comments, `#[cfg(...)]`, `#[allow(...)]`) is preserved.
        let forwarded_attrs: Vec<_> = method
            .attrs
            .iter()
            .filter(|a| !a.path().is_ident("client_trait"))
            .collect();

        // Forwarding call: `StructName::method_name(self, arg1, arg2, ...)`. Each non-receiver
        // argument is rebuilt from its binding pattern so the trait-impl method just passes
        // its bound parameters straight through.
        let method_ident = &sig.ident;
        let arg_idents: Vec<proc_macro2::TokenStream> =
            sig.inputs.iter().skip(1).map(forward_arg).collect();

        let dot_await = if sig.asyncness.is_some() {
            quote! { .await }
        } else {
            quote! {}
        };

        trait_methods.push(quote! {
            #[allow(missing_docs)]
            #( #forwarded_attrs )*
            #sig ;
        });

        impl_methods.push(quote! {
            #[allow(missing_docs)]
            #( #forwarded_attrs )*
            #sig {
                #struct_ident::#method_ident(self, #( #arg_idents ),*) #dot_await
            }
        });
    }

    let async_trait_attr = if any_async {
        quote! { #[::async_trait::async_trait] }
    } else {
        quote! {}
    };

    // Strip `#[client_trait(...)]` helper attributes from the re-emitted inherent impl so the
    // compiler doesn't complain about an unknown attribute on the still-present methods.
    for item in item_impl.items.iter_mut() {
        if let ImplItem::Fn(method) = item {
            method.attrs.retain(|a| !a.path().is_ident("client_trait"));
        }
    }

    let trait_doc = format!(
        "Trait mirror of [`{0}`]'s public API. Implemented by [`{0}`] itself and, under \
         `cfg(test)` or `feature = \"test-fixtures\"`, automatically mocked as \
         `Mock{1}` via `mockall::automock`.",
        struct_ident, trait_ident,
    );

    let expanded = quote! {
        #[doc = #trait_doc]
        #[cfg_attr(any(test, feature = "test-fixtures"), ::mockall::automock)]
        #async_trait_attr
        pub trait #trait_ident: Send + Sync {
            #( #trait_methods )*
        }

        #async_trait_attr
        impl #trait_ident for #struct_ident {
            #( #impl_methods )*
        }

        // Auto-bridge: wires `Arc<dyn #trait_ident>` into `Client::from_client`-driven
        // construction. Requires `#struct_ident: FromClient`, typically via
        // `#[derive(FromClient)]` on the struct.
        impl ::bitwarden_core::client::FromClientDyn for dyn #trait_ident {
            fn from_client_dyn(
                client: &::bitwarden_core::Client,
            ) -> ::std::sync::Arc<Self> {
                ::std::sync::Arc::new(
                    <#struct_ident as ::bitwarden_core::client::FromClient>::from_client(client),
                )
            }
        }

        #item_impl
    };

    Ok(expanded)
}

/// Extract the call-side expression for a single function argument so the generated forwarding
/// impl can invoke the inherent method by-position.
fn forward_arg(arg: &FnArg) -> proc_macro2::TokenStream {
    match arg {
        FnArg::Typed(pat_type) => {
            // Use the pattern as-is when it's an identifier (the common case); patterns like
            // tuples or `&mut x` work too because the pattern names are bound at the trait-impl
            // method's parameter list.
            let pat = &*pat_type.pat;
            quote! { #pat }
        }
        FnArg::Receiver(_) => quote! { self },
    }
}
