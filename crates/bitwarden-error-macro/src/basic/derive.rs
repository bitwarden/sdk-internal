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
    let error_struct_identifier = quote::format_ident!("JS{}", type_identifier);

    quote! {
        const _ : () = {
            #[wasm_bindgen(js_name = #type_identifier, inspectable)]
            struct #error_struct_identifier {
                #[wasm_bindgen(getter_with_clone)]
                pub message: String,
                #[wasm_bindgen(getter_with_clone)]
                pub name: String,
            }

            #[automatically_derived]
            impl From<#type_identifier> for JsValue {
                fn from(error: #type_identifier) -> Self {
                    let sdk_error = #error_struct_identifier {
                        message: error.to_string(),
                        name: stringify!(#type_identifier).to_owned(),
                    };

                    let js_error = SdkJsError::new(error.to_string());
                    js_error.set_name(format!("SdkError({})", stringify!(#type_identifier)).to_owned());
                    js_error.set_sdk_error(sdk_error.into());

                    js_error.into()
                }
            }
        };
    }
}
