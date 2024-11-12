use quote::quote;

pub(crate) fn basic_error(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(item as syn::DeriveInput);
    let type_identifier = &input.ident;

    let wasm = cfg!(feature = "wasm").then(|| basic_error_wasm(&type_identifier));
    quote! {
        #wasm
    }
    .into()
}

fn basic_error_wasm(type_identifier: &proc_macro2::Ident) -> proc_macro2::TokenStream {
    let ts_code_str = format!(
        r##"r#"
            export interface {} extends Error {{
                name: "{}";
            }};
        "#"##,
        type_identifier, type_identifier
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
                    js_error.into()
                }
            }
        };
    }
}
