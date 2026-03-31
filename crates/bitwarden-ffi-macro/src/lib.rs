//! Proc macros for FFI bindings (WASM, UniFFI).
//!
//! Provides:
//! - `#[wasm_export]` attribute macro for hiding WASM binding methods from Rust consumers.

use proc_macro::TokenStream;

mod wasm_export;

/// Attribute macro for impl blocks containing WASM bindings.
///
/// Methods within the impl block can be marked with `#[wasm_only]` to indicate they are
/// intended only for JavaScript consumers via `wasm_bindgen`, not for direct Rust usage.
///
/// For each `#[wasm_only]` method, the macro:
/// - Renames it with a `__wasm_only_` prefix (e.g. `subscribe` -> `__wasm_only_subscribe`)
/// - Adds `#[wasm_bindgen(js_name = "subscribe")]` to preserve the JS API (if no `js_name` is
///   already set)
/// - Adds `#[doc(hidden)]` to hide it from Rust documentation
/// - Adds `#[deprecated]` so it shows with strikethrough in IDE autocomplete
///
/// This must be placed **before** (above) the `#[wasm_bindgen]` attribute so it expands first.
///
/// # Example
///
/// ```ignore
/// #[wasm_export]
/// #[wasm_bindgen(js_class = IpcClient)]
/// impl JsIpcClient {
///     // Left as-is: Rust code may need to construct this type
///     #[wasm_bindgen(js_name = newWithSdkInMemorySessions)]
///     pub fn new_with_sdk_in_memory_sessions(...) -> JsIpcClient { ... }
///
///     // Mangled: Rust consumers should use the inner client directly
///     #[wasm_only]
///     pub async fn subscribe(&self) -> Result<JsIpcClientSubscription, SubscribeError> { ... }
/// }
/// ```
#[proc_macro_attribute]
pub fn wasm_export(_attr: TokenStream, item: TokenStream) -> TokenStream {
    wasm_export::wasm_export(item.into()).into()
}
