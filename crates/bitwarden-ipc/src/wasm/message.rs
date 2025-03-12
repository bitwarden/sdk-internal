use serde::{Deserialize, Serialize};

use {tsify_next::Tsify, wasm_bindgen::prelude::*};

#[derive(Tsify, Serialize, Deserialize)]
#[tsify(into_wasm_abi, from_wasm_abi)]
// #[wasm_bindgen]
pub struct JsIpcPayload {
    // pub payload: Box<[u8]>,
    pub json_payload: String,
}

impl TryFrom<Vec<u8>> for JsIpcPayload {
    type Error = serde_json::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        // Might want to consider a more efficient way to do this, like converting from the Vec<u8> directly to utf8
        let payload = serde_json::from_slice(&value)?;
        Ok(payload)
    }
}

impl TryFrom<JsIpcPayload> for Vec<u8> {
    type Error = serde_json::Error;

    fn try_from(value: JsIpcPayload) -> Result<Self, Self::Error> {
        let payload = serde_json::to_vec(&value)?;
        Ok(payload)
    }
}
