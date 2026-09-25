//! WebAssembly bindings for FIDO2 credential provider operations.
//!
//! The host contract ([crate::Fido2CredentialStore] and [crate::Fido2UserInterface]) is defined
//! in terms of owned Rust types and requires
//! `Send + Sync`, while [::wasm_bindgen] can only hand us an opaque, thread-bound [JsValue]. Each
//! bridge in this module reconciles the two in three layers:
//!
//! 1. A hand-written `typescript_custom_section` declaring the interface JavaScript must satisfy.
//! 2. An `extern "C"` block binding that interface as an opaque type. Every callback uses
//!    `#[wasm_bindgen(method, catch)]` so a JavaScript exception arrives as `Err` instead of
//!    trapping the WebAssembly instance.
//! 3. A wrapper holding the JavaScript object in a [::bitwarden_threading::ThreadBoundRunner],
//!    which pins it to its original thread and exposes a `Send` handle. This is what makes the
//!    `Send + Sync` bound on the traits satisfiable.

mod client;
mod credential_store;
mod user_interface;

use bitwarden_threading::CallError;
pub use client::{WasmFido2Authenticator, WasmFido2Client, WasmFido2WebAuthnClient};
pub use credential_store::RawJsFido2CredentialStore;
pub use user_interface::{
    CheckUserAndPickCredentialForCreationResult, Fido2UiHint, RawJsFido2UserInterface,
};
use wasm_bindgen::JsValue;

use crate::Fido2CallbackError;

/// A [ThreadBoundRunner](::bitwarden_threading::ThreadBoundRunner) call that never reached the
/// JavaScript object. Only happens if the bridge closure itself panics.
impl From<CallError> for Fido2CallbackError {
    fn from(error: CallError) -> Self {
        Fido2CallbackError::Unknown(error.to_string())
    }
}

/// Serialize a value for a JavaScript callback.
fn to_js<T: serde::Serialize>(value: &T) -> Result<JsValue, Fido2CallbackError> {
    ::tsify::serde_wasm_bindgen::to_value(value)
        .map_err(|e| Fido2CallbackError::Unknown(e.to_string()))
}

/// Deserialize a value returned by a JavaScript callback.
fn from_js<T: serde::de::DeserializeOwned>(value: JsValue) -> Result<T, Fido2CallbackError> {
    ::tsify::serde_wasm_bindgen::from_value(value)
        .map_err(|e| Fido2CallbackError::Unknown(e.to_string()))
}

/// Convert an exception thrown by a JavaScript callback into a [Fido2CallbackError].
///
/// Every rejection maps to [Fido2CallbackError::Unknown]. The other two variants are deliberately
/// unused: the authenticator flattens all callback errors to a single CTAP status code before they
/// reach the caller, so a finer-grained mapping here would carry no information across the
/// boundary. Ceremony-level signals such as "the user asked for the browser instead" travel on the
/// caller's `AbortController`, not on this error.
fn js_error(error: JsValue) -> Fido2CallbackError {
    Fido2CallbackError::Unknown(format!("{error:?}"))
}
