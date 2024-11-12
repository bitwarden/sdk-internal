use quote::quote;

pub(crate) fn basic_error(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(item as syn::DeriveInput);
    let type_identifier = &input.ident;

    let wasm = cfg!(feature = "wasm").then(|| basic_error_wasm(type_identifier));
    quote! {
        #wasm
    }
    .into()
}

fn basic_error_wasm(type_identifier: &proc_macro2::Ident) -> proc_macro2::TokenStream {
    let type_identifier_str = type_identifier.to_string();
    let is_error_function_name = format!("is{}", type_identifier);
    let ts_code_str = format!(
        r##"r#"
            export interface {type_identifier} extends Error {{
                name: "{type_identifier}";
            }};

            export function {is_error_function_name}(error: any): error is {type_identifier};
        "#"##
    );
    let ts_code: proc_macro2::TokenStream = ts_code_str
        .parse()
        .expect("Could not generate TypeScript code");

    quote! {
        const _: () = {
            use wasm_bindgen::prelude::*;

            #[wasm_bindgen(typescript_custom_section)]
            const TS_APPEND_CONTENT: &'static str = #ts_code;

            #[wasm_bindgen(js_name = #is_error_function_name, skip_typescript)]
            pub fn is_error(error: &JsValue) -> bool {
                let name_js_value = js_sys::Reflect::get(&error, &JsValue::from_str("name")).unwrap_or(JsValue::NULL);
                let name = name_js_value.as_string().unwrap_or_default();
                name == #type_identifier_str
            }

            #[automatically_derived]
            impl From<#type_identifier> for JsValue {
                fn from(error: #type_identifier) -> Self {
                    let js_error = SdkJsError::new(error.to_string());
                    js_error.set_name(#type_identifier_str.to_owned());
                    js_error.into()
                }
            }
        };
    }
}
