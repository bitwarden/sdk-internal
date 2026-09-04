use darling::Error;
use quote::quote;

pub(crate) fn bitwarden_error_full(
    input: &syn::DeriveInput,
    type_identifier: &proc_macro2::Ident,
    export_as_identifier: &proc_macro2::Ident,
) -> proc_macro::TokenStream {
    if type_identifier != export_as_identifier {
        return Error::custom("`bitwarden_error(full)` does not currently support `export_as`")
            .write_errors()
            .into();
    }

    let wasm_attributes = cfg!(feature = "wasm").then(|| {
        quote! {
            #[derive(bitwarden_error::tsify::Tsify)]
        }
    });

    // Hand-written rather than via `#[tsify(into_wasm_abi)]`: that attribute is deprecated, and its
    // generated conversion panics when serialization fails, which on wasm aborts the instance.
    // Only `From<E> for JsValue` is actually needed here, since wasm_bindgen requires no more than
    // that of a `Result`'s error type.
    let wasm_conversion = cfg!(feature = "wasm").then(|| {
        let export_as_identifier_str = export_as_identifier.to_string();
        quote! {
            const _: () = {
                use bitwarden_error::wasm_bindgen::JsValue;

                #[automatically_derived]
                impl From<#type_identifier> for JsValue {
                    fn from(error: #type_identifier) -> Self {
                        match bitwarden_error::tsify::Tsify::into_js(&error) {
                            Ok(js) => js.into(),
                            // `From` cannot report failure, so surface a named error rather than
                            // unwinding out of the conversion. The name is deliberately *not* the
                            // error's own: JavaScript narrows on it and then reads `variant`, which
                            // this value does not have. Deliberately does not use
                            // `error.to_string()` either: `full` does not require `Display`.
                            Err(err) => {
                                let js_error = ::bitwarden_error::wasm::SdkJsError::new(
                                    format!(
                                        "Failed to serialize `{}`: {}",
                                        #export_as_identifier_str, err,
                                    ),
                                );
                                js_error.set_name(
                                    ::bitwarden_error::wasm::CONVERSION_ERROR_NAME.to_owned(),
                                );
                                js_error.into()
                            }
                        }
                    }
                }
            };
        }
    });

    quote! {
        #[derive(serde::Serialize)]
        #[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
        #wasm_attributes
        #input

        #wasm_conversion
    }
    .into()
}
