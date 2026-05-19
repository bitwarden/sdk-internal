//! Expansion logic for `#[client_trait]`.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Error, Expr, FnArg, ImplItem, ItemImpl, Type, Visibility};

/// Expands `#[client_trait(...)]` on an inherent impl block into:
/// - the original impl (with helper attrs stripped)
/// - a `FooTrait` mirror trait (with `#[mockall::automock]` under cfg(test) / test-fixtures)
/// - an `impl FooTrait for Foo` that forwards to the inherent methods
/// - optionally, an `impl FromClientShared for dyn FooTrait` bridge if `via = <expr>` was given
pub(crate) fn expand(
    mut item_impl: ItemImpl,
    via_expr: Option<Expr>,
) -> Result<TokenStream, Error> {
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
        let arg_idents: Vec<TokenStream> = sig.inputs.iter().skip(1).map(forward_arg).collect();

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

    // Auto-bridge wiring `Arc<dyn #trait_ident>` into `Client::from_client`-driven construction.
    // Only emitted when the caller provides `via = <expression>`. The expression is plugged into
    // the bridge body with `client: &Client` in scope and must evaluate to the concrete struct.
    let bridge = via_expr.map(|expr| {
        quote! {
            impl ::bitwarden_core::client::FromClientShared for dyn #trait_ident {
                fn from_client_shared(
                    client: &::bitwarden_core::Client,
                ) -> ::std::sync::Arc<Self> {
                    ::std::sync::Arc::new(#expr)
                }
            }
        }
    });

    Ok(quote! {
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

        #bridge

        #item_impl
    })
}

/// Extract the call-side expression for a single function argument so the generated forwarding
/// impl can invoke the inherent method by-position.
fn forward_arg(arg: &FnArg) -> TokenStream {
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
