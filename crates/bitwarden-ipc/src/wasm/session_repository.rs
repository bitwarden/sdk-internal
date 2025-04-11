use bitwarden_error::bitwarden_error;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tsify_next::serde_wasm_bindgen;
use wasm_bindgen::prelude::*;

use crate::{endpoint::Endpoint, traits::SessionRepository};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[wasm_bindgen(js_name = "IpcSession")]
pub struct JsSession();

#[derive(Debug, Error)]
#[bitwarden_error(basic)]
#[error("Failed to deserialize: {0}")]
pub struct DeserializeError(String);

#[wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export interface SessionRepository {
    get(destination: Endpoint): Promise<IpcSession>;
    save(destination: Endpoint, session: IpcSession): Promise<void>;
    remove(destination: Endpoint): Promise<void>;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = SessionRepository, typescript_type = "SessionRepository")]
    pub type JsSessionRepository;

    #[wasm_bindgen(catch, method, structural)]
    async fn get(this: &JsSessionRepository, destination: Endpoint) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(catch, method, structural)]
    async fn save(
        this: &JsSessionRepository,
        destination: Endpoint,
        session: JsSession,
    ) -> Result<(), JsValue>;
    #[wasm_bindgen(catch, method, structural)]
    async fn remove(this: &JsSessionRepository, destination: Endpoint) -> Result<(), JsValue>;
}

impl SessionRepository for JsSessionRepository {
    type Session = JsSession;
    type GetError = JsValue;
    type SaveError = JsValue;
    type RemoveError = JsValue;

    async fn get(&self, destination: Endpoint) -> Result<Option<Self::Session>, Self::GetError> {
        self.get(destination).await.and_then(|result| {
            if result.is_null() || result.is_undefined() {
                return Ok(None);
            }

            let result: Self::Session = serde_wasm_bindgen::from_value(result)
                .map_err(|e| DeserializeError(e.to_string()))?;

            Ok(Some(result))
        })
    }

    async fn save(
        &self,
        destination: Endpoint,
        session: Self::Session,
    ) -> Result<(), Self::SaveError> {
        self.save(destination, session).await
    }

    async fn remove(&self, destination: Endpoint) -> Result<(), Self::RemoveError> {
        self.remove(destination).await
    }
}
