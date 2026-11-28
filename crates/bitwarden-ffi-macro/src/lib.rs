//! Proc macros for FFI bindings (WASM, UniFFI).
//!
//! Provides:
//! - `#[wasm_export]` attribute macro for an impl block or free function exported to JavaScript.
//! - `#[wasm_record]` attribute macro for a type that crosses the ABI through serde.
//! - `#[wasm_object]` attribute macro for a type that crosses the ABI as a handle.
//! - `#[wasm_import]` attribute macro for an `extern "C"` block of JavaScript imports.
//!
//! Each macro **replaces** the attribute it stands in for rather than decorating it, so an item
//! carries one of these and no `#[wasm_bindgen]` or `#[tsify]` of its own. That is what lets the
//! expansion change without touching call sites.
//!
//! An expansion names only `bitwarden_ffi`, so a call site imports nothing — but the crate has to
//! forward its own `wasm` feature to `bitwarden-ffi/wasm`, which is where those names live.

use proc_macro::TokenStream;

mod attrs;
mod ts_type;
mod wasm_export;
mod wasm_import;
mod wasm_object;
mod wasm_record;
mod wire;

/// Exports an impl block or a free function to JavaScript, in place of
/// `#[cfg_attr(feature = "wasm", wasm_bindgen(..))]`.
///
/// The item is left exactly as written, so Rust and UniFFI callers see its plain signature. A
/// second `#[wasm_bindgen]` block of `__wasm_ts_*` shims is generated beside it, and only those
/// name the wire types: each parameter is projected onto `<T as FromWasm>::Wire` and each return
/// onto `<T as ToWasm>::Wire`, with the conversion in the shim body. References pass through as
/// written.
///
/// Every `pub` method is shimmed, matching wasm_bindgen's own rule, and every shim is fallible even
/// where nothing can fail — wasm_bindgen renders `Result<T, E>` as `T` plus a throw, so the
/// TypeScript is identical. A method's own `#[wasm_bindgen(..)]` moves onto its shim.
///
/// Arguments are forwarded to `#[wasm_bindgen]`, so `#[wasm_export(js_class = Foo)]` behaves as it
/// would there. The item must not be generic; wasm_bindgen cannot export generic items.
///
/// # `#[wasm_only]`
///
/// Marks a method whose only intended caller is JavaScript, because Rust has a better API for the
/// same thing. The method is renamed with a `__wasm_only_` prefix, hidden from documentation, and
/// marked `#[deprecated]` so it shows struck through in IDE autocomplete. Takes an optional
/// `note = "..."` for that deprecation. The JS name is unaffected: it lives on the shim, which
/// calls the renamed method.
///
/// # Stream return types
///
/// wasm_bindgen types a `BwStream<T>` as `any`. To give JavaScript a real type, a method that
/// returns a `BwStream<T>`, or a `Result` whose `Ok` is one, gets an `unchecked_return_type` worked
/// out from the Rust type: `AsyncIterable<T>`, where a `Result<T, E>` item becomes
/// `BwResult<T, E>`.
///
/// The item type is translated like this:
///
/// - `Box<T>` becomes `T`.
/// - `Vec<T>` becomes `T[]`, or a typed array for numbers.
/// - `Option<T>` becomes `T | undefined`.
/// - Primitives map as they do in wasm_bindgen.
/// - Any other type becomes the last segment of its path, so `crate::vault::CipherListView` becomes
///   `CipherListView`.
///
/// The last rule gives the wrong name when the TypeScript name differs from the Rust one: a type
/// renamed with `js_name` or `#[serde(rename)]`, or one used through a type alias. Write
/// `unchecked_return_type` yourself in those cases. Tuples, `Self`, references other than `&str`,
/// and generic types not listed above fail to compile until you write it. An
/// `unchecked_return_type` you write always replaces the inferred one.
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

/// Declares a type that crosses the wasm ABI through serde, as `Ts<Self>`.
///
/// Derives `Tsify` and implements `FromWasm` / `ToWasm`, so a `#[wasm_export]` signature naming
/// this type projects onto `Ts<Self>` and converts inside the shim body, where a failure is an
/// ordinary `Err`.
///
/// `#[serde(..)]` and `#[tsify(..)]` attributes are left in place for `Tsify`'s derive to read, and
/// the `#[derive(..)]` for `Serialize` / `Deserialize` / UniFFI stays where it is — this macro only
/// owns the wasm side.
///
/// `#[wasm_record(input)]` declares only the JavaScript-to-Rust direction, for a type that must not
/// be serialized back out (for example, one holding a password).
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

/// Declares a block of JavaScript imports, in place of `#[wasm_bindgen]` on an `extern "C"` block.
///
/// Arguments are forwarded to `#[wasm_bindgen]`, and the attributes inside the block are left for
/// it to read. Each `type` the block declares also gets the wire traits, so it can appear in a
/// `#[wasm_export]` signature. Unlike the other macros, `#[wasm_bindgen]` is applied
/// unconditionally: an extern block cannot compile without it, so the block's own `cfg` decides.
///
/// A `catch` import takes Rust types for its by-value parameters. The import itself is renamed to
/// a hidden `__wasm_raw_*` function taking each parameter's `<T as ToWasm>::Wire`, and a wrapper
/// with the declared signature converts the arguments and calls it; a failed conversion is the
/// wrapper's `Err`. An `Ok` type other than `()` or `JsValue` is received as its
/// `<T as FromWasm>::Wire` and converted the same way. An import without `catch` has nowhere to
/// report a failed conversion, so it, and any getter, setter, constructor, or variadic import, is
/// passed through unchanged.
///
/// ```ignore
/// #[wasm_import]
/// extern "C" {
///     #[wasm_bindgen(js_name = SharedUnlockDriver)]
///     pub type RawJsSharedUnlockDriver;
///
///     #[wasm_bindgen(method, catch)]
///     async fn lock_user(this: &RawJsSharedUnlockDriver, user_id: UserId) -> Result<(), JsValue>;
/// }
/// ```
#[proc_macro_attribute]
pub fn wasm_import(attr: TokenStream, item: TokenStream) -> TokenStream {
    wasm_import::wasm_import(attr.into(), item.into()).into()
}
