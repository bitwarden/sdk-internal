use tsify_next::serde_wasm_bindgen;
use wasm_bindgen::prelude::*;

use crate::{message::Message, traits::CommunicationBackend};

#[wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export interface CommunicationBackend {
    send(message: Message): Promise<void>;
    receive(): Promise<Message>;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = CommunicationBackend, typescript_type = "CommunicationBackend")]
    pub type JsCommunicationBackend;

    #[wasm_bindgen(catch, method, structural)]
    pub async fn send(this: &JsCommunicationBackend, message: Message) -> Result<(), JsValue>;

    #[wasm_bindgen(catch, method, structural)]
    pub async fn receive(this: &JsCommunicationBackend) -> Result<JsValue, JsValue>;
}

impl CommunicationBackend for JsCommunicationBackend {
    type SendError = JsValue;
    type ReceiveError = JsValue;

    async fn send(&self, message: Message) -> Result<(), Self::SendError> {
        self.send(message).await
    }

    async fn receive(&self) -> Result<Message, Self::ReceiveError> {
        let js_value = self.receive().await?;
        let message: Message = serde_wasm_bindgen::from_value(js_value)
            .map_err(|e| format!("Failed to deserialize message: {e}"))?;
        Ok(message)
    }
}

// #[wasm_bindgen
