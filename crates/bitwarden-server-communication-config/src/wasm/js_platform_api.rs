use bitwarden_threading::ThreadBoundRunner;
use wasm_bindgen::prelude::*;

use crate::{AcquiredCookie, ServerCommunicationConfigPlatformApi};

#[wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
/**
 * Acquired cookie structure
 */
export interface AcquiredCookie {
    name: string;
    value: string;
}

/**
 * Platform API interface for acquiring SSO cookies.
 * 
 * Platform clients implement this interface to handle cookie acquisition
 * through browser redirects or other platform-specific mechanisms.
 */
export interface ServerCommunicationConfigPlatformApi {
    /**
     * Acquires a cookie for the given hostname.
     * 
     * This typically involves redirecting to an IdP login page and extracting
     * the cookie from the load balancer response.
     * 
     * @param hostname The server hostname (e.g., "vault.acme.com")
     * @returns An AcquiredCookie object, or undefined if acquisition failed or was cancelled
     */
    acquireCookie(hostname: string): Promise<AcquiredCookie | undefined>;
}
"#;

#[wasm_bindgen]
extern "C" {
    /// JavaScript interface for the ServerCommunicationConfigPlatformApi
    #[wasm_bindgen(
        js_name = ServerCommunicationConfigPlatformApi,
        typescript_type = "ServerCommunicationConfigPlatformApi"
    )]
    pub type RawJsServerCommunicationConfigPlatformApi;

    /// Acquires a cookie for a hostname
    #[wasm_bindgen(catch, method, structural, js_name = acquireCookie)]
    pub async fn acquire_cookie(
        this: &RawJsServerCommunicationConfigPlatformApi,
        hostname: String,
    ) -> Result<JsValue, JsValue>;
}

/// Thread-safe JavaScript implementation of ServerCommunicationConfigPlatformApi
///
/// This wrapper ensures the JavaScript platform API can be safely used across
/// threads in WASM environments by using ThreadBoundRunner to pin operations
/// to the main thread.
pub struct JsServerCommunicationConfigPlatformApi(
    ThreadBoundRunner<RawJsServerCommunicationConfigPlatformApi>,
);

impl JsServerCommunicationConfigPlatformApi {
    /// Creates a new JsServerCommunicationConfigPlatformApi wrapping the raw JavaScript platform
    /// API
    pub fn new(platform_api: RawJsServerCommunicationConfigPlatformApi) -> Self {
        Self(ThreadBoundRunner::new(platform_api))
    }
}

impl Clone for JsServerCommunicationConfigPlatformApi {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[async_trait::async_trait]
impl ServerCommunicationConfigPlatformApi for JsServerCommunicationConfigPlatformApi {
    async fn acquire_cookie(&self, hostname: String) -> Option<AcquiredCookie> {
        self.0
            .run_in_thread(move |platform_api| async move {
                let js_value = platform_api
                    .acquire_cookie(hostname)
                    .await
                    .map_err(|e| format!("{e:?}"))?;

                if js_value.is_undefined() || js_value.is_null() {
                    return Ok(None);
                }

                let cookie: AcquiredCookie =
                    serde_wasm_bindgen::from_value(js_value).map_err(|e| e.to_string())?;
                Ok(Some(cookie))
            })
            .await
            .ok()
            .and_then(|result: Result<Option<AcquiredCookie>, String>| result.ok())
            .flatten()
    }
}
