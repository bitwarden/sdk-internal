use quote::quote;

pub(crate) fn bitwarden_error_basic(
    input: &syn::DeriveInput,
    type_identifier: &proc_macro2::Ident,
    export_as_identifier: &proc_macro2::Ident,
) -> proc_macro::TokenStream {
    let wasm =
        cfg!(feature = "wasm").then(|| basic_error_wasm(type_identifier, export_as_identifier));
    quote! {
        #input

        #wasm
    }
    .into()
}

fn basic_error_wasm(
    type_identifier: &proc_macro2::Ident,
    export_as_identifier: &proc_macro2::Ident,
) -> proc_macro2::TokenStream {
    let export_as_identifier_str = export_as_identifier.to_string();
    let is_error_function_name = format!("is{}", export_as_identifier);
    let ts_code_str = format!(
        r##"r#"
            export interface {export_as_identifier} extends Error {{
                name: "{export_as_identifier}";
            }}

            export function {is_error_function_name}(error: any): error is {export_as_identifier};
        "#"##
    );
    let ts_code: proc_macro2::TokenStream = ts_code_str
        .parse()
        .expect("Could not generate TypeScript code");

    quote! {
        const _: () = {
            use bitwarden_error::wasm_bindgen::prelude::*;
            use bitwarden_error::wasm_bindgen as wasm_bindgen;

            #[wasm_bindgen(typescript_custom_section)]
            const TS_APPEND_CONTENT: &'static str = #ts_code;

            #[wasm_bindgen(js_name = #is_error_function_name, skip_typescript)]
            pub fn is_error(error: &JsValue) -> bool {
                let name_js_value = ::bitwarden_error::js_sys::Reflect::get(&error, &JsValue::from_str("name")).unwrap_or(JsValue::NULL);
                let name = name_js_value.as_string().unwrap_or_default();
                name == #export_as_identifier_str
            }

            #[automatically_derived]
            impl From<#type_identifier> for JsValue {
                fn from(error: #type_identifier) -> Self {
                    let js_error = ::bitwarden_error::wasm::SdkJsError::new(error.to_string());
                    js_error.set_name(#export_as_identifier_str.to_owned());
                    js_error.into()
                }
            }
        };
    }
}
