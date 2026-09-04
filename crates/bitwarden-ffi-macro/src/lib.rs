//! Proc macros for FFI bindings (WASM, UniFFI).
//!
//! Provides:
//! - `#[wasm_export]` attribute macro for generating an impl block's WASM bindings.
//! - `#[wasm_record]` attribute macro for a type that crosses the ABI through serde.
//! - `#[wasm_object]` attribute macro for a type that crosses the ABI as a handle.
//!
//! The two type-level macros exist so `#[wasm_export]` does not have to guess which kind a type is.
//! A proc macro cannot resolve types, so each type declares its own wire form at its declaration
//! site and the shim just spells a projection. See `bitwarden_ffi::wire`.

use proc_macro::TokenStream;

mod wasm_export;
mod wasm_object;
mod wasm_record;

/// Generates the WASM bindings for an impl block or a free function, in place of
/// `#[wasm_bindgen]`.
///
/// Put this on a **plain** item — do not also apply `#[wasm_bindgen]`. The original is left as
/// written, and a `#[cfg(feature = "wasm")] #[wasm_bindgen]` shim is generated beside it. That
/// separation is what lets one Rust function serve Rust, UniFFI and JavaScript at once: the shim
/// adapts the signature for JavaScript without the other targets seeing it.
///
/// On an impl block, every `pub` method is exported, matching `#[wasm_bindgen]`'s own rule, and
/// each method's `#[wasm_bindgen(..)]` attributes are moved onto its shim. Arguments to this macro
/// are forwarded to the generated block, so `#[wasm_export(js_class = Foo)]` behaves as it would on
/// `#[wasm_bindgen]`. On a free function they are forwarded to the shim itself, so
/// `#[wasm_export(js_name = doThing)]` behaves the same way.
///
/// # Value conversion
///
/// Values that cross via serde are passed as `tsify::Ts<T>` and converted inside the shim body,
/// where a failure is an ordinary `Err` and destructors run. `#[tsify(from_wasm_abi)]` instead
/// converts inside `FromWasmAbi::from_abi`, which cannot fail and so calls
/// `wasm_bindgen::throw_str`, leaking everything live at that point
/// ([tsify#65](https://github.com/madonoharu/tsify/issues/65)).
///
/// Every parameter and return value is projected onto `<T as FromWasm>::Wire` /
/// `<T as ToWasm>::Wire`, and the type itself decides what that resolves to: `#[wasm_record]` makes
/// it `Ts<T>`, `#[wasm_object]` makes it `T`. `Vec<T>` and `Option<T>` compose through blanket
/// impls, so `Vec<u8>` stays a `Uint8Array` while `Vec<CipherView>` becomes `Vec<Ts<CipherView>>`.
/// References are passed through untouched. A type that declares neither kind is a missing-impl
/// compile error naming the site.
///
/// The item must not be generic; wasm_bindgen cannot export generic items.
///
/// A method returning `Result<T, E>` yields `Result<_, TsError<E>>`, and `TsError::Inner` delegates
/// to `E`'s own `From<E> for JsValue` — so a `bitwarden_error` type reaches JavaScript with the
/// `name` and `variant` it already had. Conversion failures surface as an `Error` named
/// `SdkConversionError`. Every shim is fallible, including the ones where nothing can fail — the
/// macro cannot know whether a given type's conversion is infallible, and the generated `Result` is
/// invisible to JavaScript, since wasm_bindgen renders `Result<T, E>` as `T` plus a throw.
///
/// # `#[wasm_only]`
///
/// Marks a method whose only intended caller is JavaScript, because Rust has a better API for the
/// same thing. The method is renamed with a `__wasm_only_` prefix, hidden from documentation, and
/// marked `#[deprecated]` so it shows struck through in IDE autocomplete. Takes an optional
/// `note = "..."` for that deprecation. The JS name is unaffected: it belongs to the shim, which
/// calls the renamed method.
///
/// # Example
///
/// ```ignore
/// #[wasm_export(js_class = IpcClient)]
/// impl JsIpcClient {
///     // `OutgoingRequest` is `#[wasm_record]`, so `request` crosses as `Ts<OutgoingRequest>`.
///     pub async fn send(&self, request: OutgoingRequest) -> Result<Response, SendError> { ... }
///
///     // Exported to JavaScript, but invisible to Rust — use `IpcClient::start` instead.
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
/// Derives `Tsify` under the `wasm` feature and implements `FromWasm` / `ToWasm` so the type
/// crosses as `Ts<Self>`. `#[serde(..)]` and `#[tsify(..)]` attributes are left in place for
/// `Tsify`'s derive to read, and the `#[derive(..)]` for `Serialize` / `Deserialize` / UniFFI stays
/// where it is — this macro only owns the wasm side.
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
/// `#[cfg_attr(feature = "wasm", wasm_bindgen)]`.
///
/// Applies `#[wasm_bindgen]` under the `wasm` feature and implements `FromWasm` / `ToWasm` so the
/// type crosses as itself. Arguments are forwarded to `#[wasm_bindgen]`, so
/// `#[wasm_object(js_name = Ciphers)]` behaves as it would there.
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
