use bitwarden_threading::ThreadBoundRunner;
use wasm_bindgen::prelude::*;

use crate::{ServerCommunicationConfig, ServerCommunicationConfigRepository};

#[wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
/**
 * Repository interface for storing server communication configuration.
 * 
 * Implementations use StateProvider (or equivalent storage mechanism) to
 * persist configuration across sessions. The hostname is typically the vault
 * server's hostname (e.g., "vault.acme.com").
 */
export interface ServerCommunicationConfigRepository {
    /**
     * Retrieves the server communication configuration for a given hostname.
     * 
     * @param hostname The server hostname (e.g., "vault.acme.com")
     * @returns The configuration if it exists, undefined otherwise
     */
    get(hostname: string): Promise<ServerCommunicationConfig | undefined>;
    
    /**
     * Saves the server communication configuration for a given hostname.
     * 
     * @param hostname The server hostname (e.g., "vault.acme.com")
     * @param config The configuration to store
     */
    save(hostname: string, config: ServerCommunicationConfig): Promise<void>;
}
"#;

#[wasm_bindgen]
extern "C" {
    /// JavaScript interface for the ServerCommunicationConfigRepository
    #[wasm_bindgen(
        js_name = ServerCommunicationConfigRepository,
        typescript_type = "ServerCommunicationConfigRepository"
    )]
    pub type RawJsServerCommunicationConfigRepository;

    /// Retrieves configuration for a hostname
    #[wasm_bindgen(catch, method, structural)]
    pub async fn get(
        this: &RawJsServerCommunicationConfigRepository,
        hostname: String,
    ) -> Result<JsValue, JsValue>;

    /// Saves configuration for a hostname
    #[wasm_bindgen(catch, method, structural)]
    pub async fn save(
        this: &RawJsServerCommunicationConfigRepository,
        hostname: String,
        config: JsValue,
    ) -> Result<(), JsValue>;
}

/// Thread-safe JavaScript implementation of ServerCommunicationConfigRepository
///
/// This wrapper ensures the JavaScript repository can be safely used across
/// threads in WASM environments by using ThreadBoundRunner to pin operations
/// to the main thread.
pub struct JsServerCommunicationConfigRepository(
    ThreadBoundRunner<RawJsServerCommunicationConfigRepository>,
);

impl JsServerCommunicationConfigRepository {
    /// Creates a new JsServerCommunicationConfigRepository wrapping the raw JavaScript repository
    pub fn new(repository: RawJsServerCommunicationConfigRepository) -> Self {
        Self(ThreadBoundRunner::new(repository))
    }
}

impl Clone for JsServerCommunicationConfigRepository {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
impl ServerCommunicationConfigRepository for JsServerCommunicationConfigRepository {
    type GetError = String;
    type SaveError = String;

    async fn get(&self, hostname: String) -> Result<Option<ServerCommunicationConfig>, String> {
        self.0
            .run_in_thread(move |repo| async move {
                let js_value = repo.get(hostname).await.map_err(|e| format!("{e:?}"))?;

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

    async fn save(
        &self,
        hostname: String,
        config: ServerCommunicationConfig,
    ) -> Result<(), String> {
        self.0
            .run_in_thread(move |repo| async move {
                let js_value = serde_wasm_bindgen::to_value(&config).map_err(|e| e.to_string())?;
                repo.save(hostname, js_value)
                    .await
                    .map_err(|e| format!("{e:?}"))
            })
            .await
            .map_err(|e| e.to_string())?
    }
}
