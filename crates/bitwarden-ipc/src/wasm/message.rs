use std::str;

use wasm_bindgen::prelude::*;

use crate::{
    endpoint::Endpoint,
    message::{IncomingMessage, OutgoingMessage},
};

#[wasm_bindgen]
impl OutgoingMessage {
    #[wasm_bindgen(constructor)]
    pub fn new(payload: Vec<u8>, destination: Endpoint, topic: Option<String>) -> OutgoingMessage {
        OutgoingMessage {
            payload,
            destination,
            topic,
        }
    }

    /// Create a new message and encode the payload as JSON.
    pub fn new_json_payload(
        payload: JsValue,
        destination: Endpoint,
        topic: Option<String>,
    ) -> Result<OutgoingMessage, JsValue> {
        let payload = js_sys::JSON::stringify(&payload)?;
        let payload: String = payload
            .as_string()
            .ok_or_else(|| JsValue::from_str("Failed to convert JSON payload to string"))?;
        let payload = payload.into_bytes();
        Ok(OutgoingMessage {
            payload,
            destination,
            topic,
        })
    }
}

#[wasm_bindgen]
impl IncomingMessage {
    #[wasm_bindgen(constructor)]
    pub fn new(
        payload: Vec<u8>,
        destination: Endpoint,
        source: Endpoint,
        topic: Option<String>,
    ) -> IncomingMessage {
        IncomingMessage {
            payload,
            destination,
            source,
            topic,
        }
    }

    /// Try to parse the payload as JSON.
    #[wasm_bindgen(
        return_description = "The parsed JSON value, or undefined if the payload is not valid JSON."
    )]
    pub fn parse_payload_as_json(&self) -> JsValue {
        str::from_utf8(&self.payload)
            .ok()
            .and_then(|payload| js_sys::JSON::parse(payload).ok())
            .unwrap_or(JsValue::UNDEFINED)
    }
}
