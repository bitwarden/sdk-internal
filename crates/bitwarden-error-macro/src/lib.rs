use darling::{ast::NestedMeta, FromMeta};
use quote::quote;
use syn::Data;

#[derive(FromMeta)]
struct BitwardenErrorArgs {
    #[darling(flatten)]
    error_type: BitwardenErrorType,
}

#[derive(FromMeta)]
enum BitwardenErrorType {
    /// The error is going to be converted into a string using the `ToString` trait
    #[darling(rename = "basic")]
    Basic,

    /// The error is going to be converted into a flat error using the `FlatError` trait
    #[darling(rename = "flat")]
    Flat,

    /// The entire error stack is going to be made available using `serde`
    #[darling(rename = "basic")]
    Full,
}

#[proc_macro_attribute]
pub fn bitwarden_error(
    args: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    let attr_args = match NestedMeta::parse_meta_list(args.into()) {
        Ok(v) => v,
        Err(e) => {
            return proc_macro::TokenStream::from(darling::Error::from(e).write_errors());
        }
    };

    let BitwardenErrorArgs { error_type } = match BitwardenErrorArgs::from_list(&attr_args) {
        Ok(params) => params,
        Err(error) => {
            return proc_macro::TokenStream::from(darling::Error::from(error).write_errors());
        }
    };

    let input = syn::parse_macro_input!(item as syn::DeriveInput);
    match error_type {
        BitwardenErrorType::Basic => basic_error_impl(&input),
        BitwardenErrorType::Flat => flat_error_impl(&input),
        BitwardenErrorType::Full => full_error_impl(&input),
    }
}

fn basic_error_impl(input: &syn::DeriveInput) -> proc_macro::TokenStream {
    quote! {
        #[derive(BasicError)]
        #input
    }
    .into()
}

fn flat_error_impl(input: &syn::DeriveInput) -> proc_macro::TokenStream {
    let type_identifier = &input.ident;

    quote! {
        #[derive(FlatError)]
        #input

        impl BitwardenError for #type_identifier {}
    }
    .into()
}

fn full_error_impl(input: &syn::DeriveInput) -> proc_macro::TokenStream {
    quote! {}.into()
}

#[proc_macro_derive(BasicError)]
pub fn basic_error(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(item as syn::DeriveInput);
    let type_identifier = &input.ident;

    let js_value = basic_error_js_value(&type_identifier);
    quote! {
        #js_value
    }
    .into()
}

#[cfg(feature = "wasm")]
fn basic_error_js_value(type_identifier: &proc_macro2::Ident) -> proc_macro2::TokenStream {
    quote! {
        #[automatically_derived]
        impl From<#type_identifier> for JsValue {
            fn from(error: #type_identifier) -> Self {
                let js_error = JsError::new(error.to_string());
                js_error.set_name(stringify!(#type_identifier).to_owned());
                js_error.into()
            }
        }
    }
}

#[cfg(not(feature = "wasm"))]
fn basic_error_js_value(type_identifier: &proc_macro2::Ident) -> proc_macro2::TokenStream {
    quote! {}
}

#[proc_macro_derive(FlatError)]
pub fn flat_error(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(item as syn::DeriveInput);
    let type_identifier = &input.ident;

    match &input.data {
        Data::Enum(data) => {
            let variant_names = data.variants.iter().map(|variant| &variant.ident);

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

            let types = types(&type_identifier, &variant_names.collect::<Vec<_>>());

            quote! {
                #types

                #[automatically_derived]
                impl FlatError for #type_identifier {
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
                impl FlatError for #type_identifier {
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

#[cfg(feature = "wasm")]
fn types(
    type_identifier: &proc_macro2::Ident,
    variant_names: &[&proc_macro2::Ident],
) -> proc_macro2::TokenStream {
    let ts_identifier = quote::format_ident!("TS_TYPES_{}", type_identifier);
    let ts_code_str = format!(
        r##"r#"
            export interface {} extends Error {{
                name: "{}";
                variant: {};
            }};
        "#"##,
        type_identifier,
        type_identifier,
        variant_names
            .iter()
            .map(|vn| format!(r#""{vn}""#))
            .collect::<Vec<String>>()
            .join("|")
    );
    let ts_code: proc_macro2::TokenStream = ts_code_str.parse().unwrap();

    quote! {
        #[wasm_bindgen(typescript_custom_section)]
        const #ts_identifier: &'static str = #ts_code;
    }
}

#[cfg(not(feature = "wasm"))]
fn types(
    type_identifier: &proc_macro2::Ident,
    variant_names: &[&proc_macro2::Ident],
) -> proc_macro2::TokenStream {
    quote! {}
}
