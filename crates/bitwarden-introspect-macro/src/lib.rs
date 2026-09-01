//! Derive macro for `bitwarden-introspect`.
//!
//! Provides `#[derive(Introspect)]`, which implements the `Introspect` trait
//! for a struct so it can be walked by the introspection/discovery API.

use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DataStruct, DeriveInput, Fields, parse_macro_input};

/// Derive `Introspect` for a struct with named fields.
///
/// Each field becomes a child edge keyed by its name. Descent recurses into
/// the field's own `Introspect` impl, so the whole reachable graph is walkable
/// one path segment at a time.
///
/// Field attributes:
/// - `#[introspect(skip)]` — omit the field from the graph entirely.
/// - `#[introspect(writable)]` — report the child as `CloneReplace` writable
///   (the owning container can clone the field, apply a change, and store it
///   back). Fields typed as `Debuggable<T>` already report `InPlace` on their
///   own and don't need this.
#[proc_macro_derive(Introspect, attributes(introspect))]
pub fn derive_introspect(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let name = &input.ident;
    let name_str = name.to_string();
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let Data::Struct(DataStruct {
        fields: Fields::Named(fields),
        ..
    }) = &input.data
    else {
        return syn::Error::new_spanned(
            &input,
            "Introspect can currently only be derived for structs with named fields",
        )
        .to_compile_error()
        .into();
    };

    let mut child_pushes = Vec::new();
    let mut describe_arms = Vec::new();

    for field in &fields.named {
        let Some(ident) = field.ident.as_ref() else {
            continue;
        };
        let key = ident.to_string();

        let mut skip = false;
        let mut writable = false;
        for attr in &field.attrs {
            if attr.path().is_ident("introspect") {
                // Best-effort attribute parse; unknown keys are ignored in this sketch.
                let _ = attr.parse_nested_meta(|meta| {
                    if meta.path.is_ident("skip") {
                        skip = true;
                    } else if meta.path.is_ident("writable") {
                        writable = true;
                    }
                    Ok(())
                });
            }
        }
        if skip {
            continue;
        }

        let writeability_override = if writable {
            quote! {
                __child.writeability = ::bitwarden_introspect::Writeability::CloneReplace;
            }
        } else {
            quote! {}
        };

        child_pushes.push(quote! {
            {
                let __node = ::bitwarden_introspect::Introspect::node_info(&self.#ident);
                let mut __child = ::bitwarden_introspect::ChildRef {
                    key: #key.to_string(),
                    type_name: __node.type_name,
                    preview: __node.preview,
                    writeability: __node.writeability,
                };
                #writeability_override
                __children.push(__child);
            }
        });

        describe_arms.push(quote! {
            #key => ::bitwarden_introspect::Introspect::describe(&self.#ident, __rest),
        });
    }

    quote! {
        impl #impl_generics ::bitwarden_introspect::Introspect for #name #ty_generics #where_clause {
            fn node_info(&self) -> ::bitwarden_introspect::NodeInfo {
                let mut __children = ::std::vec::Vec::new();
                #(#child_pushes)*
                ::bitwarden_introspect::NodeInfo {
                    type_name: #name_str,
                    preview: ::std::format!("{} {{ .. }}", #name_str),
                    writeability: ::bitwarden_introspect::Writeability::ReadOnly,
                    children: __children,
                }
            }

            fn describe(
                &self,
                __path: &[&str],
            ) -> ::core::option::Option<::bitwarden_introspect::NodeInfo> {
                match __path.split_first() {
                    ::core::option::Option::None => {
                        ::core::option::Option::Some(::bitwarden_introspect::Introspect::node_info(self))
                    }
                    ::core::option::Option::Some((__head, __rest)) => match *__head {
                        #(#describe_arms)*
                        _ => ::core::option::Option::None,
                    },
                }
            }
        }
    }
    .into()
}
