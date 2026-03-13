use bitwarden_threading::ThreadBoundRunner;
use serde::{Serialize, de::DeserializeOwned};
use tsify::serde_wasm_bindgen;
use wasm_bindgen::prelude::*;

use crate::{endpoint::Endpoint, traits::SessionRepository};

#[wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export interface IpcSessionRepository {
    get(endpoint: Endpoint): Promise<any | undefined>;
    save(endpoint: Endpoint, session: any): Promise<void>;
    remove(endpoint: Endpoint): Promise<void>;
}
"#;

#[wasm_bindgen]
extern "C" {
    /// JavaScript interface for handling outgoing messages from the IPC framework.
    #[wasm_bindgen(js_name = IpcSessionRepository, typescript_type = "IpcSessionRepository")]
    pub type RawJsSessionRepository;

    /// Used by the IPC framework to get a session for a specific endpoint.
    #[wasm_bindgen(catch, method, structural)]
    pub async fn get(this: &RawJsSessionRepository, endpoint: Endpoint)
    -> Result<JsValue, JsValue>;

    /// Used by the IPC framework to save a session for a specific endpoint.
    #[wasm_bindgen(catch, method, structural)]
    pub async fn save(
        this: &RawJsSessionRepository,
        endpoint: Endpoint,
        session: JsValue,
    ) -> Result<(), JsValue>;

    /// Used by the IPC framework to remove a session for a specific endpoint.
    #[wasm_bindgen(catch, method, structural)]
    pub async fn remove(this: &RawJsSessionRepository, endpoint: Endpoint) -> Result<(), JsValue>;
}

/// Thread safe JavaScript implementation of the `SessionRepository` trait for IPC sessions.
pub struct JsSessionRepository(ThreadBoundRunner<RawJsSessionRepository>);

unsafe impl Send for RawJsSessionRepository {}
unsafe impl Sync for RawJsSessionRepository {}

impl JsSessionRepository {
    /// Creates a new `JsSessionRepository` instance wrapping the raw JavaScript repository.
    pub fn new(repository: RawJsSessionRepository) -> Self {
        Self(ThreadBoundRunner::new(repository))
    }
}

impl Clone for JsSessionRepository {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<Session> SessionRepository<Session> for JsSessionRepository
where
    Session: Serialize + DeserializeOwned + Send + Sync + 'static,
{
    type GetError = String;
    type SaveError = String;
    type RemoveError = String;

    async fn get(&self, endpoint: Endpoint) -> Result<Option<Session>, Self::GetError> {
        self.0
            .run_in_thread(move |repo| async move {
                let js_value = repo.get(endpoint).await.map_err(|e| format!("{e:?}"))?;
                if js_value.is_undefined() || js_value.is_null() {
                    return Ok(None);
                }

                Ok(Some(
                    serde_wasm_bindgen::from_value(js_value).map_err(|e| e.to_string())?,
                ))
            })
            .await
            .map_err(|e| e.to_string())?
    }

    async fn save(&self, endpoint: Endpoint, session: Session) -> Result<(), Self::SaveError> {
        self.0
            .run_in_thread(move |repo| async move {
                let js_value = serde_wasm_bindgen::to_value(&session).map_err(|e| e.to_string())?;
                repo.save(endpoint, js_value)
                    .await
                    .map_err(|e| format!("{e:?}"))
            })
            .await
            .map_err(|e| e.to_string())?
    }

    async fn remove(&self, endpoint: Endpoint) -> Result<(), Self::RemoveError> {
        self.0
            .run_in_thread(move |repo| async move {
                repo.remove(endpoint).await.map_err(|e| format!("{e:?}"))
            })
            .await
            .map_err(|e| e.to_string())?
    }
}
