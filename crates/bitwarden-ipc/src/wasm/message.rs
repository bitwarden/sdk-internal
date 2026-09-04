use std::str;

use bitwarden_ffi::{Ts, TsError};
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
}

// `destination` is `#[wasm_bindgen(skip)]` on the struct, so its accessors live here. The generated
// pair would take and return `Endpoint` directly, which is the `from_wasm_abi` path this crate has
// moved off; going through `Ts<Endpoint>` keeps the failure an ordinary `Err`.
#[wasm_bindgen]
impl OutgoingMessage {
    #[wasm_bindgen(getter)]
    /// Destination endpoint for this message.
    pub fn destination(&self) -> Result<Ts<Endpoint>, TsError> {
        Ts::from_rust(&self.destination).map_err(TsError::Conversion)
    }

    #[wasm_bindgen(setter)]
    /// Sets the destination endpoint for this message.
    pub fn set_destination(&mut self, destination: Ts<Endpoint>) -> Result<(), TsError> {
        self.destination = destination.to_rust().map_err(TsError::Conversion)?;
        Ok(())
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
}

// As above: `destination` and `source` are `#[wasm_bindgen(skip)]` on the struct.
#[wasm_bindgen]
impl IncomingMessage {
    #[wasm_bindgen(getter)]
    /// Destination endpoint that received this message.
    pub fn destination(&self) -> Result<Ts<Endpoint>, TsError> {
        Ts::from_rust(&self.destination).map_err(TsError::Conversion)
    }

    #[wasm_bindgen(setter)]
    /// Sets the destination endpoint that received this message.
    pub fn set_destination(&mut self, destination: Ts<Endpoint>) -> Result<(), TsError> {
        self.destination = destination.to_rust().map_err(TsError::Conversion)?;
        Ok(())
    }

    #[wasm_bindgen(getter)]
    /// Source that sent this message, with per-variant metadata.
    pub fn source(&self) -> Result<Ts<Source>, TsError> {
        Ts::from_rust(&self.source).map_err(TsError::Conversion)
    }

    #[wasm_bindgen(setter)]
    /// Sets the source that sent this message.
    pub fn set_source(&mut self, source: Ts<Source>) -> Result<(), TsError> {
        self.source = source.to_rust().map_err(TsError::Conversion)?;
        Ok(())
    }
}
