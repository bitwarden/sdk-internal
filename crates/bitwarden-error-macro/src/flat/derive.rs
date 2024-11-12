use quote::quote;
use syn::Data;

pub(crate) fn flat_error(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(item as syn::DeriveInput);
    let type_identifier = &input.ident;

    match &input.data {
        Data::Enum(data) => {
            let variant_names = data.variants.iter().map(|variant| &variant.ident);

            let match_arms = data.variants.iter().map(|variant| match variant.fields {
                syn::Fields::Unit => {
                    let variant_ident = &variant.ident;
                    let variant_name = format!("{}", variant_ident);
                    quote! {
                        #type_identifier::#variant_ident => #variant_name
                    }
                }
                syn::Fields::Named(_) => {
                    let variant_ident = &variant.ident;
                    let variant_name = format!("{}", variant_ident);
                    quote! {
                        #type_identifier::#variant_ident { .. } => #variant_name
                    }
                }
                syn::Fields::Unnamed(_) => {
                    let variant_ident = &variant.ident;
                    let variant_name = format!("{}", variant_ident);
                    quote! {
                        #type_identifier::#variant_ident(..) => #variant_name
                    }
                }
            });

            let wasm = cfg!(feature = "wasm")
                .then(|| flat_error_wasm(&type_identifier, &variant_names.collect::<Vec<_>>()));

            quote! {
                #wasm

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
        _ => syn::Error::new_spanned(input, "bitwarden_error can only be used with enums")
            .to_compile_error()
            .into(),
    }
}

fn flat_error_wasm(
    type_identifier: &proc_macro2::Ident,
    variant_names: &[&proc_macro2::Ident],
) -> proc_macro2::TokenStream {
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
        const _: () = {
            #[wasm_bindgen(typescript_custom_section)]
            const TS_APPEND_CONTENT: &'static str = #ts_code;

            #[automatically_derived]
            impl From<#type_identifier> for JsValue {
                fn from(error: #type_identifier) -> Self {
                    let js_error = JsError::new(error.to_string());
                    js_error.set_name(stringify!(#type_identifier).to_owned());
                    js_error.set_variant(error.error_variant().to_owned());
                    js_error.into()
                }
            }
        };
    }
}
