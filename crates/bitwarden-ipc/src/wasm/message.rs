use std::str;

use wasm_bindgen::prelude::*;

use crate::{
    endpoint::{Endpoint, Source},
    message::{IncomingMessage, OutgoingMessage},
};

#[bitwarden_ffi::wasm_export]
impl OutgoingMessage {
    #[wasm_bindgen(constructor)]
    /// Create an outgoing IPC message from raw payload bytes.
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

    #[wasm_only(note = "Read the `destination` field.")]
    #[wasm_bindgen(getter)]
    /// Destination endpoint for this message.
    pub fn destination(&self) -> Endpoint {
        self.destination.clone()
    }

    #[wasm_only(note = "Write the `destination` field.")]
    #[wasm_bindgen(setter = destination)]
    /// Sets the destination endpoint for this message.
    pub fn set_destination(&mut self, destination: Endpoint) {
        self.destination = destination;
    }
}

#[bitwarden_ffi::wasm_export]
impl IncomingMessage {
    #[wasm_bindgen(constructor)]
    /// Create an incoming IPC message from raw payload bytes.
    pub fn new(
        payload: Vec<u8>,
        destination: Endpoint,
        source: Source,
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

    #[wasm_only(note = "Read the `destination` field.")]
    #[wasm_bindgen(getter)]
    /// Destination endpoint that received this message.
    pub fn destination(&self) -> Endpoint {
        self.destination.clone()
    }

    #[wasm_only(note = "Write the `destination` field.")]
    #[wasm_bindgen(setter = destination)]
    /// Sets the destination endpoint that received this message.
    pub fn set_destination(&mut self, destination: Endpoint) {
        self.destination = destination;
    }

    #[wasm_only(note = "Read the `source` field.")]
    #[wasm_bindgen(getter)]
    /// Source that sent this message, with per-variant metadata.
    pub fn source(&self) -> Source {
        self.source.clone()
    }

    #[wasm_only(note = "Write the `source` field.")]
    #[wasm_bindgen(setter = source)]
    /// Sets the source that sent this message.
    pub fn set_source(&mut self, source: Source) {
        self.source = source;
    }
}
