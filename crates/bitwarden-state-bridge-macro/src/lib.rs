//! Proc macro for generating the key-management state bridge surface.
//!
//! Provides the `state_bridge!` function-like macro that, from a list of typed fields, expands
//! into the `StateBridgeImpl` trait, wrapper methods on `StateBridge` and `StateBridgeClient`,
//! WASM extern bindings, the `WasmStateBridge` trait impl, and the matching TypeScript interface.

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{
    Ident, LitStr, Token, Type,
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
};

mod state_bridge_kw {
    syn::custom_keyword!(ts);
}

struct StateBridgeField {
    name: Ident,
    ty: Type,
    ts: LitStr,
}

impl Parse for StateBridgeField {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let name: Ident = input.parse()?;
        input.parse::<Token![:]>()?;
        let ty: Type = input.parse()?;
        input.parse::<Token![as]>()?;
        input.parse::<state_bridge_kw::ts>()?;
        let ts: LitStr = input.parse()?;
        Ok(Self { name, ty, ts })
    }
}

struct StateBridgeInput {
    fields: Punctuated<StateBridgeField, Token![,]>,
}

impl Parse for StateBridgeInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Self {
            fields: Punctuated::parse_terminated(input)?,
        })
    }
}

/// Generates the full state bridge surface for a fixed list of fields.
///
/// Each field expands to:
/// 1. Three methods on the `StateBridgeImpl` trait (`set_$name`, `get_$name`, `clear_$name`).
/// 2. Three corresponding wrapper methods on `StateBridge`.
/// 3. Three corresponding methods on `StateBridgeClient`.
/// 4. Three method declarations on the WASM `RawWasmStateBridge` extern type and three forwarders
///    in the `StateBridgeImpl` impl for `WasmStateBridge`.
/// 5. Three lines in the `WasmStateBridge` TypeScript interface.
/// 6. One field on `test_support::InMemoryStateBridge` and three forwarders in its
///    `StateBridgeImpl` impl, gated on `#[cfg(test)]`.
///
/// All fields share the same shape: `set_$name(value: $ty)`, `get_$name() -> Option<$ty>`,
/// `clear_$name()`.
#[proc_macro]
pub fn state_bridge(input: TokenStream) -> TokenStream {
    let StateBridgeInput { fields } = parse_macro_input!(input as StateBridgeInput);

    let trait_methods = fields.iter().map(|f| {
        let ty = &f.ty;
        let n = f.name.to_string();
        let set = format_ident!("set_{}", f.name);
        let get = format_ident!("get_{}", f.name);
        let clear = format_ident!("clear_{}", f.name);
        let set_doc = format!("Stores the `{n}` value.");
        let get_doc = format!("Returns the `{n}` value, if available.");
        let clear_doc = format!("Clears the `{n}` value.");
        quote! {
            #[doc = #set_doc]
            async fn #set(&self, value: #ty);
            #[doc = #get_doc]
            async fn #get(&self) -> Option<#ty>;
            #[doc = #clear_doc]
            async fn #clear(&self);
        }
    });

    let bridge_wrappers = fields.iter().map(|f| {
        let ty = &f.ty;
        let n = f.name.to_string();
        let set = format_ident!("set_{}", f.name);
        let get = format_ident!("get_{}", f.name);
        let clear = format_ident!("clear_{}", f.name);
        let set_doc = format!("Stores the `{n}` value.");
        let get_doc = format!("Returns the `{n}` value, if available.");
        let clear_doc = format!("Clears the `{n}` value.");
        quote! {
            #[doc = #set_doc]
            pub async fn #set(&self, value: &#ty) {
                let implementation = self
                    .implementation
                    .lock()
                    .expect("Mutex is not poisoned")
                    .as_ref()
                    .expect("StateBridge not registered")
                    .clone();
                implementation.#set(value.to_owned()).await
            }

            #[doc = #get_doc]
            pub async fn #get(&self) -> Option<#ty> {
                let implementation = self
                    .implementation
                    .lock()
                    .expect("Mutex is not poisoned")
                    .as_ref()
                    .expect("StateBridge not registered")
                    .clone();
                implementation.#get().await
            }

            #[doc = #clear_doc]
            pub async fn #clear(&self) {
                let implementation = self
                    .implementation
                    .lock()
                    .expect("Mutex is not poisoned")
                    .as_ref()
                    .expect("StateBridge not registered")
                    .clone();
                implementation.#clear().await
            }
        }
    });

    let client_forwarders = fields.iter().map(|f| {
        let ty = &f.ty;
        let n = f.name.to_string();
        let set = format_ident!("set_{}", f.name);
        let get = format_ident!("get_{}", f.name);
        let clear = format_ident!("clear_{}", f.name);
        let set_doc = format!("Sets the `{n}` value in client-managed state.");
        let get_doc = format!("Gets the `{n}` value from client-managed state, if available.");
        let clear_doc = format!("Clears the `{n}` value from client-managed state.");
        quote! {
            #[doc = #set_doc]
            pub async fn #set(&self, value: &#ty) {
                self.client.internal.state_bridge.#set(value).await;
            }

            #[doc = #get_doc]
            pub async fn #get(&self) -> Option<#ty> {
                self.client.internal.state_bridge.#get().await
            }

            #[doc = #clear_doc]
            pub async fn #clear(&self) {
                self.client.internal.state_bridge.#clear().await;
            }
        }
    });

    let mut ts_iface = String::from(
        "/**\n * Typescript interface that the state bridge needs to implement. The state bridge\n * is a temporary layer that allows quickly transitioning non-repository shaped\n * state to be accessible from within the SDK.\n */\nexport interface WasmStateBridge {\n",
    );
    for f in &fields {
        let n = f.name.to_string();
        let t = f.ts.value();
        ts_iface.push_str(&format!("    set_{n}(value: {t}): Promise<void>;\n"));
        ts_iface.push_str(&format!("    get_{n}(): Promise<{t} | null>;\n"));
        ts_iface.push_str(&format!("    clear_{n}(): Promise<void>;\n"));
    }
    ts_iface.push_str("}\n");

    let extern_methods = fields.iter().map(|f| {
        let ty = &f.ty;
        let n = f.name.to_string();
        let set = format_ident!("set_{}", f.name);
        let get = format_ident!("get_{}", f.name);
        let clear = format_ident!("clear_{}", f.name);
        let set_doc = format!("JS-side `set_{n}` method on `WasmStateBridge`.");
        let get_doc = format!("JS-side `get_{n}` method on `WasmStateBridge`.");
        let clear_doc = format!("JS-side `clear_{n}` method on `WasmStateBridge`.");
        quote! {
            #[doc = #set_doc]
            #[wasm_bindgen(method)]
            pub async fn #set(
                this: &crate::key_management::state_bridge::RawWasmStateBridge,
                value: #ty,
            );
            #[doc = #get_doc]
            #[wasm_bindgen(method)]
            pub async fn #get(
                this: &crate::key_management::state_bridge::RawWasmStateBridge,
            ) -> Option<#ty>;
            #[doc = #clear_doc]
            #[wasm_bindgen(method)]
            pub async fn #clear(
                this: &crate::key_management::state_bridge::RawWasmStateBridge,
            );
        }
    });

    let test_support_struct_fields = fields.iter().map(|f| {
        let name = &f.name;
        let ty = &f.ty;
        quote! { #name: ::std::sync::Mutex<Option<#ty>>, }
    });

    let test_support_impl_methods = fields.iter().map(|f| {
        let name = &f.name;
        let ty = &f.ty;
        let set = format_ident!("set_{}", f.name);
        let get = format_ident!("get_{}", f.name);
        let clear = format_ident!("clear_{}", f.name);
        quote! {
            async fn #set(&self, value: #ty) {
                *self.#name.lock().expect("not poisoned") = Some(value);
            }
            async fn #get(&self) -> Option<#ty> {
                self.#name.lock().expect("not poisoned").clone()
            }
            async fn #clear(&self) {
                *self.#name.lock().expect("not poisoned") = None;
            }
        }
    });

    let wasm_impls = fields.iter().map(|f| {
        let ty = &f.ty;
        let set = format_ident!("set_{}", f.name);
        let get = format_ident!("get_{}", f.name);
        let clear = format_ident!("clear_{}", f.name);
        quote! {
            async fn #set(&self, value: #ty) {
                self.0
                    .run_in_thread(move |state| async move {
                        state.#set(value).await
                    })
                    .await
                    .expect("State bridge call panicked");
            }
            async fn #get(&self) -> Option<#ty> {
                self.0
                    .run_in_thread(|state| async move {
                        state.#get().await
                    })
                    .await
                    .expect("State bridge call panicked")
            }
            async fn #clear(&self) {
                self.0
                    .run_in_thread(|state| async move {
                        state.#clear().await
                    })
                    .await
                    .expect("State bridge call panicked");
            }
        }
    });

    let expanded = quote! {
        /// Host-provided storage bridge for key-management state.
        ///
        /// SDK consumers register an implementation that persists or caches sensitive
        /// account state across unlock flows.
        #[cfg_attr(target_arch = "wasm32", ::async_trait::async_trait(?Send))]
        #[cfg_attr(not(target_arch = "wasm32"), ::async_trait::async_trait)]
        pub trait StateBridgeImpl: Send + Sync {
            #(#trait_methods)*
        }

        impl StateBridge {
            #(#bridge_wrappers)*
        }

        impl crate::key_management::state_bridge::StateBridgeClient {
            #(#client_forwarders)*
        }

        #[cfg(target_arch = "wasm32")]
        #[::wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
        const TS_CUSTOM_TYPES_STATE_BRIDGE: &'static str = #ts_iface;

        #[cfg(target_arch = "wasm32")]
        #[::wasm_bindgen::prelude::wasm_bindgen]
        extern "C" {
            #(#extern_methods)*
        }

        #[cfg(target_arch = "wasm32")]
        #[::async_trait::async_trait(?Send)]
        impl StateBridgeImpl for crate::key_management::state_bridge::WasmStateBridge {
            #(#wasm_impls)*
        }

        #[cfg(test)]
        pub(crate) mod test_support {
            use super::*;

            /// In-memory `StateBridgeImpl` for use in tests.
            #[derive(Default)]
            pub(crate) struct InMemoryStateBridge {
                #(#test_support_struct_fields)*
            }

            #[cfg_attr(target_arch = "wasm32", ::async_trait::async_trait(?Send))]
            #[cfg_attr(not(target_arch = "wasm32"), ::async_trait::async_trait)]
            impl super::StateBridgeImpl for InMemoryStateBridge {
                #(#test_support_impl_methods)*
            }
        }
    };

    TokenStream::from(expanded)
}
