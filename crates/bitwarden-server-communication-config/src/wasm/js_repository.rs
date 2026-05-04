use bitwarden_threading::ThreadBoundRunner;
use wasm_bindgen::prelude::*;

use crate::{ServerCommunicationConfig, ServerCommunicationConfigRepository};

#[wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
/**
 * Repository interface for storing server communication configuration.
 * 
 * Implementations use StateProvider (or equivalent storage mechanism) to
 * persist configuration across sessions. The domain is typically the vault
 * server's domain name (e.g., "vault.acme.com").
 */
export interface ServerCommunicationConfigRepository {
    /**
     * Retrieves the server communication configuration for a given domain.
     * 
     * @param domain The server domain (e.g., "vault.acme.com")
     * @returns The configuration if it exists, undefined otherwise
     */
    get(domain: string): Promise<ServerCommunicationConfig | undefined>;
    
    /**
     * Saves the server communication configuration for a given domain.
     * 
     * @param domain The server domain (e.g., "vault.acme.com")
     * @param config The configuration to store
     */
    save(domain: string, config: ServerCommunicationConfig): Promise<void>;
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

    /// Retrieves configuration for a domain
    #[wasm_bindgen(catch, method, structural)]
    pub async fn get(
        this: &RawJsServerCommunicationConfigRepository,
        domain: String,
    ) -> Result<JsValue, JsValue>;

    /// Saves configuration for a domain
    #[wasm_bindgen(catch, method, structural)]
    pub async fn save(
        this: &RawJsServerCommunicationConfigRepository,
        domain: String,
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

impl ServerCommunicationConfigRepository for JsServerCommunicationConfigRepository {
    type GetError = String;
    type SaveError = String;

    async fn get(&self, domain: String) -> Result<Option<ServerCommunicationConfig>, String> {
        self.0
            .run_in_thread(move |repo| async move {
                let js_value = repo.get(domain).await.map_err(|e| format!("{e:?}"))?;

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

    async fn save(&self, domain: String, config: ServerCommunicationConfig) -> Result<(), String> {
        self.0
            .run_in_thread(move |repo| async move {
                let js_value = serde_wasm_bindgen::to_value(&config).map_err(|e| e.to_string())?;
                repo.save(domain, js_value)
                    .await
                    .map_err(|e| format!("{e:?}"))
            })
            .await
            .map_err(|e| e.to_string())?
    }
}
