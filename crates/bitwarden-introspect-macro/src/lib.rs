//! Derive macro for `bitwarden-introspect`.
//!
//! Provides `#[derive(Introspect)]`, which implements the `Introspect` trait
//! for a struct (named fields) or an enum so it can be walked by the
//! introspection/discovery API.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{Data, DataEnum, DataStruct, DeriveInput, Fields, FieldsNamed, parse_macro_input};

/// Derive `Introspect` for a struct with named fields, or for an enum.
///
/// For structs, each field becomes a child edge keyed by its name. For enums,
/// the active variant's name is the node preview and its fields (named or
/// positional) are the children.
///
/// Struct field attributes:
/// - `#[introspect(skip)]` — omit the field from the graph entirely.
/// - `#[introspect(writable)]` — report the child as `CloneReplace` writable.
///   Fields typed as `Debuggable<T>` already report `InPlace` and don't need
///   this.
#[proc_macro_derive(Introspect, attributes(introspect))]
pub fn derive_introspect(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let name = &input.ident;
    let name_str = name.to_string();
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let (node_info_body, describe_body) = match &input.data {
        Data::Struct(DataStruct {
            fields: Fields::Named(fields),
            ..
        }) => struct_bodies(&name_str, fields),
        Data::Enum(data) => enum_bodies(&name_str, data),
        _ => {
            return syn::Error::new_spanned(
                &input,
                "Introspect can be derived for structs with named fields or for enums",
            )
            .to_compile_error()
            .into();
        }
    };

    quote! {
        impl #impl_generics ::bitwarden_introspect::Introspect for #name #ty_generics #where_clause {
            fn node_info(&self) -> ::bitwarden_introspect::NodeInfo {
                #node_info_body
            }

            fn describe(
                &self,
                __path: &[&str],
            ) -> ::core::option::Option<::bitwarden_introspect::NodeInfo> {
                #describe_body
            }
        }
    }
    .into()
}

/// Derive `IntrospectWrite` for a struct with named fields.
///
/// Every field is writable by default; the write dispatches into the field's
/// own `IntrospectWrite` impl. Opt a field out with `#[introspect(skip_write)]`
/// — that field's type is then never referenced, so it need not be
/// `Deserialize` (this is how a struct with a non-serde field still derives).
/// A struct node cannot be replaced wholesale; callers address a field.
#[proc_macro_derive(IntrospectWrite, attributes(introspect))]
pub fn derive_introspect_write(item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as DeriveInput);
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let Data::Struct(DataStruct {
        fields: Fields::Named(fields),
        ..
    }) = &input.data
    else {
        return syn::Error::new_spanned(
            &input,
            "IntrospectWrite can currently only be derived for structs with named fields",
        )
        .to_compile_error()
        .into();
    };

    let mut arms = Vec::new();
    for field in &fields.named {
        let Some(ident) = field.ident.as_ref() else {
            continue;
        };
        let key = ident.to_string();

        let mut skip_write = false;
        for attr in &field.attrs {
            if attr.path().is_ident("introspect") {
                let _ = attr.parse_nested_meta(|meta| {
                    if meta.path.is_ident("skip_write") {
                        skip_write = true;
                    }
                    Ok(())
                });
            }
        }

        if skip_write {
            arms.push(quote! {
                #key => ::core::result::Result::Err(
                    ::bitwarden_introspect::WriteError::NotWritable(#key.to_string())
                ),
            });
        } else {
            arms.push(quote! {
                #key => ::bitwarden_introspect::IntrospectWrite::set(
                    &mut self.#ident, __rest, __value,
                ),
            });
        }
    }

    quote! {
        impl #impl_generics ::bitwarden_introspect::IntrospectWrite for #name #ty_generics #where_clause {
            fn set(
                &mut self,
                __path: &[&str],
                __value: ::bitwarden_introspect::JsonValue,
            ) -> ::core::result::Result<(), ::bitwarden_introspect::WriteError> {
                match __path.split_first() {
                    ::core::option::Option::None => {
                        ::core::result::Result::Err(::bitwarden_introspect::WriteError::WholeNode)
                    }
                    ::core::option::Option::Some((__head, __rest)) => match *__head {
                        #(#arms)*
                        _ => ::core::result::Result::Err(
                            ::bitwarden_introspect::WriteError::NotFound(__head.to_string())
                        ),
                    },
                }
            }
        }
    }
    .into()
}

fn struct_bodies(name_str: &str, fields: &FieldsNamed) -> (TokenStream2, TokenStream2) {
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
            quote! { __child.writeability = ::bitwarden_introspect::Writeability::CloneReplace; }
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

    let node_info = quote! {
        let mut __children = ::std::vec::Vec::new();
        #(#child_pushes)*
        ::bitwarden_introspect::NodeInfo {
            type_name: #name_str,
            preview: ::std::format!("{} {{ .. }}", #name_str),
            writeability: ::bitwarden_introspect::Writeability::ReadOnly,
            children: __children,
        }
    };

    let describe = quote! {
        match __path.split_first() {
            ::core::option::Option::None => {
                ::core::option::Option::Some(::bitwarden_introspect::Introspect::node_info(self))
            }
            ::core::option::Option::Some((__head, __rest)) => match *__head {
                #(#describe_arms)*
                _ => ::core::option::Option::None,
            },
        }
    };

    (node_info, describe)
}

fn enum_bodies(name_str: &str, data: &DataEnum) -> (TokenStream2, TokenStream2) {
    let mut node_arms = Vec::new();
    let mut describe_arms = Vec::new();

    for variant in &data.variants {
        let vident = &variant.ident;
        let vstr = vident.to_string();
        let (pattern, pushes, field_arms) = variant_parts(&variant.fields);

        node_arms.push(quote! {
            Self::#vident #pattern => {
                let mut __children = ::std::vec::Vec::new();
                #(#pushes)*
                ::bitwarden_introspect::NodeInfo {
                    type_name: #name_str,
                    preview: #vstr.to_string(),
                    writeability: ::bitwarden_introspect::Writeability::ReadOnly,
                    children: __children,
                }
            }
        });

        describe_arms.push(quote! {
            Self::#vident #pattern => match *__head {
                #(#field_arms)*
                _ => ::core::option::Option::None,
            },
        });
    }

    let node_info = quote! {
        match self {
            #(#node_arms)*
        }
    };

    let describe = quote! {
        match __path.split_first() {
            ::core::option::Option::None => {
                ::core::option::Option::Some(::bitwarden_introspect::Introspect::node_info(self))
            }
            ::core::option::Option::Some((__head, __rest)) => match self {
                #(#describe_arms)*
            },
        }
    };

    (node_info, describe)
}

/// For one enum variant, produce its match pattern, the child-push statements
/// for `node_info`, and the per-field arms for `describe`.
fn variant_parts(fields: &Fields) -> (TokenStream2, Vec<TokenStream2>, Vec<TokenStream2>) {
    match fields {
        Fields::Named(named) => {
            let idents: Vec<_> = named
                .named
                .iter()
                .filter_map(|f| f.ident.clone())
                .collect();
            let pattern = quote! { { #(#idents),* } };
            let pushes = idents
                .iter()
                .map(|ident| {
                    let key = ident.to_string();
                    push_child(&key, quote! { #ident })
                })
                .collect();
            let arms = idents
                .iter()
                .map(|ident| {
                    let key = ident.to_string();
                    quote! { #key => ::bitwarden_introspect::Introspect::describe(#ident, __rest), }
                })
                .collect();
            (pattern, pushes, arms)
        }
        Fields::Unnamed(unnamed) => {
            let binds: Vec<_> = (0..unnamed.unnamed.len())
                .map(|i| format_ident!("__f{}", i))
                .collect();
            let pattern = quote! { ( #(#binds),* ) };
            let pushes = binds
                .iter()
                .enumerate()
                .map(|(i, bind)| push_child(&i.to_string(), quote! { #bind }))
                .collect();
            let arms = binds
                .iter()
                .enumerate()
                .map(|(i, bind)| {
                    let key = i.to_string();
                    quote! { #key => ::bitwarden_introspect::Introspect::describe(#bind, __rest), }
                })
                .collect();
            (pattern, pushes, arms)
        }
        Fields::Unit => (quote! {}, Vec::new(), Vec::new()),
    }
}

/// A `node_info` child-push statement for a bound value expression.
fn push_child(key: &str, value: TokenStream2) -> TokenStream2 {
    quote! {
        {
            let __node = ::bitwarden_introspect::Introspect::node_info(#value);
            __children.push(::bitwarden_introspect::ChildRef {
                key: #key.to_string(),
                type_name: __node.type_name,
                preview: __node.preview,
                writeability: __node.writeability,
            });
        }
    }
}
