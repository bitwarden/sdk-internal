//! Proc macros for FFI bindings (WASM, UniFFI).
//!
//! Provides:
//! - `#[wasm_export]` attribute macro for an impl block or free function exported to JavaScript.
//! - `#[wasm_record]` attribute macro for a type that crosses the ABI through serde.
//! - `#[wasm_object]` attribute macro for a type that crosses the ABI as a handle.
//!
//! Each macro **replaces** the attribute it stands in for rather than decorating it, so an item
//! carries one of these and no `#[wasm_bindgen]` or `#[tsify]` of its own. That is what lets the
//! expansion change without touching call sites.
//!
//! An expansion names only `bitwarden_ffi`, so a call site imports nothing — but the crate has to
//! forward its own `wasm` feature to `bitwarden-ffi/wasm`, which is where those names live.

use proc_macro::TokenStream;

mod attrs;
mod wasm_export;
mod wasm_object;
mod wasm_record;

/// Exports an impl block or a free function to JavaScript, in place of
/// `#[cfg_attr(feature = "wasm", wasm_bindgen(..))]`.
///
/// Arguments are forwarded to `#[wasm_bindgen]`, so `#[wasm_export(js_class = Foo)]` behaves as it
/// would there. The item must not be generic; wasm_bindgen cannot export generic items.
///
/// # `#[wasm_only]`
///
/// Marks a method whose only intended caller is JavaScript, because Rust has a better API for the
/// same thing. The method is renamed with a `__wasm_only_` prefix, hidden from documentation, and
/// marked `#[deprecated]` so it shows struck through in IDE autocomplete. Takes an optional
/// `note = "..."` for that deprecation. The JS name is unaffected: the original name is declared as
/// the method's `js_name`, unless it already declares one.
///
/// # Example
///
/// ```ignore
/// #[wasm_export(js_class = IpcClient)]
/// impl JsIpcClient {
///     pub async fn send(&self, message: OutgoingMessage) -> Result<(), SendError> { ... }
///
///     // Exported to JavaScript, but struck through for Rust — use `IpcClient::start` instead.
///     #[wasm_only(note = "Use `IpcClient::start`.")]
///     pub async fn start(&self) -> Result<(), AlreadyRunningError> { ... }
/// }
/// ```
#[proc_macro_attribute]
pub fn wasm_export(attr: TokenStream, item: TokenStream) -> TokenStream {
    wasm_export::wasm_export(attr.into(), item.into()).into()
}

/// Declares a type that crosses the wasm ABI through serde, in place of
/// `#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]`.
///
/// `#[serde(..)]` and `#[tsify(..)]` attributes are left in place for `Tsify`'s derive to read, and
/// the `#[derive(..)]` for `Serialize` / `Deserialize` / UniFFI stays where it is — this macro only
/// owns the wasm side. Takes no arguments.
///
/// ```ignore
/// #[wasm_record]
/// #[derive(Serialize, Deserialize)]
/// #[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
/// #[serde(rename_all = "camelCase")]
/// pub struct CipherView { pub id: Option<CipherId> }
/// ```
#[proc_macro_attribute]
pub fn wasm_record(attr: TokenStream, item: TokenStream) -> TokenStream {
    wasm_record::wasm_record(attr.into(), item.into()).into()
}

/// Declares a type that crosses the wasm ABI as an opaque handle, in place of
/// `#[cfg_attr(feature = "wasm", wasm_bindgen(..))]` on a struct or an enum.
///
/// Arguments are forwarded to `#[wasm_bindgen]`, so `#[wasm_object(js_name = Ciphers)]` behaves as
/// it would there.
///
/// ```ignore
/// #[wasm_object]
/// #[derive(Clone)]
/// pub struct CiphersClient { client: Client }
/// ```
#[proc_macro_attribute]
pub fn wasm_object(attr: TokenStream, item: TokenStream) -> TokenStream {
    wasm_object::wasm_object(attr.into(), item.into()).into()
}
