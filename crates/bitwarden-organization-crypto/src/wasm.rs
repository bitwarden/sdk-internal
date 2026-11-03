//! The wasm module holds serialization/encoding needed wasm bindings for
//! any types related to Invite. In order to minimize complexity, the actual
//! encoding/decoding is limited to the `From<String>` and `FromStr`
//! implementations. All other serialization goes through String to simplify
//! maintenance.
use std::str::FromStr;

use crate::invite::{Invite, InviteKeyBundleError, InviteSecret};

bitwarden_ffi::impl_wire_string!(
    Invite,
    parse = |wire: String| wire.parse(),
    format = |invite: Invite| String::from(&invite),
);
bitwarden_ffi::impl_wire_string!(
    InviteSecret,
    parse = |wire: String| wire.parse(),
    format = |secret: InviteSecret| String::from(&secret),
);

impl TryFrom<wasm_bindgen::JsValue> for Invite {
    type Error = InviteKeyBundleError;

    fn try_from(value: wasm_bindgen::JsValue) -> Result<Self, Self::Error> {
        let string = value
            .as_string()
            .ok_or(InviteKeyBundleError::DecodingFailed)?;
        Self::from_str(&string)
    }
}

impl TryFrom<wasm_bindgen::JsValue> for InviteSecret {
    type Error = InviteKeyBundleError;

    fn try_from(value: wasm_bindgen::JsValue) -> Result<Self, Self::Error> {
        let string = value
            .as_string()
            .ok_or(InviteKeyBundleError::DecodingFailed)?;
        Self::from_str(&string)
    }
}

// Returning these types from `async` `#[wasm_bindgen]` methods (which resolve to JS Promises)
// requires `Into<JsValue>`, not just `IntoWasmAbi`. Both delegate through their base64 string form.
impl From<Invite> for wasm_bindgen::JsValue {
    fn from(value: Invite) -> Self {
        wasm_bindgen::JsValue::from_str(&String::from(&value))
    }
}

impl From<InviteSecret> for wasm_bindgen::JsValue {
    fn from(value: InviteSecret) -> Self {
        wasm_bindgen::JsValue::from_str(&String::from(&value))
    }
}
