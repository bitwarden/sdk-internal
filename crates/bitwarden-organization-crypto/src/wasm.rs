//! The wasm module holds serialization/encoding needed wasm bindings for
//! any types related to InviteKeyEnvelope. This means base64url for the
//! InviteKeyData type, and Bitwarden EncString text format (`"2.iv|data|mac"`)
//! for the InviteKeyEnvelope type. In order to minimize complexity, the actual
//! encoding/decoding is limited to the `From<String>` and `FromStr`
//! implementations. All other serialization goes through String to simplify
//! maintenance.
use std::str::FromStr;

use wasm_bindgen::convert::{FromWasmAbi, IntoWasmAbi, OptionFromWasmAbi};

use crate::{Invite, InviteKeyBundleError, InviteKeyData};

impl wasm_bindgen::describe::WasmDescribe for InviteKeyData {
    fn describe() {
        <String as wasm_bindgen::describe::WasmDescribe>::describe();
    }
}

impl FromWasmAbi for InviteKeyData {
    type Abi = <String as FromWasmAbi>::Abi;

    unsafe fn from_abi(abi: Self::Abi) -> Self {
        use wasm_bindgen::UnwrapThrowExt;
        let string = unsafe { String::from_abi(abi) };
        InviteKeyData::from_str(&string).unwrap_throw()
    }
}

impl OptionFromWasmAbi for InviteKeyData {
    fn is_none(abi: &Self::Abi) -> bool {
        <String as OptionFromWasmAbi>::is_none(abi)
    }
}

impl IntoWasmAbi for InviteKeyData {
    type Abi = <String as IntoWasmAbi>::Abi;

    fn into_abi(self) -> Self::Abi {
        String::from(&self).into_abi()
    }
}

impl TryFrom<wasm_bindgen::JsValue> for InviteKeyData {
    type Error = InviteKeyBundleError;

    fn try_from(value: wasm_bindgen::JsValue) -> Result<Self, Self::Error> {
        let string = value
            .as_string()
            .ok_or(InviteKeyBundleError::DecodingFailed)?;
        Self::from_str(&string)
    }
}

#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type Invite = Tagged<string, "Invite">;
"#;

impl wasm_bindgen::describe::WasmDescribe for Invite {
    fn describe() {
        <String as wasm_bindgen::describe::WasmDescribe>::describe();
    }
}

impl FromWasmAbi for Invite {
    type Abi = <String as FromWasmAbi>::Abi;

    unsafe fn from_abi(abi: Self::Abi) -> Self {
        use wasm_bindgen::UnwrapThrowExt;
        let string = unsafe { String::from_abi(abi) };
        Invite::from_str(&string).unwrap_throw()
    }
}

impl OptionFromWasmAbi for Invite {
    fn is_none(abi: &Self::Abi) -> bool {
        <String as OptionFromWasmAbi>::is_none(abi)
    }
}

impl IntoWasmAbi for Invite {
    type Abi = <String as IntoWasmAbi>::Abi;

    fn into_abi(self) -> Self::Abi {
        String::from(&self).into_abi()
    }
}

impl TryFrom<wasm_bindgen::JsValue> for Invite {
    type Error = InviteKeyBundleError;

    fn try_from(value: wasm_bindgen::JsValue) -> Result<Self, Self::Error> {
        let string = value
            .as_string()
            .ok_or(InviteKeyBundleError::DecodingFailed)?;
        Self::from_str(&string)
    }
}
