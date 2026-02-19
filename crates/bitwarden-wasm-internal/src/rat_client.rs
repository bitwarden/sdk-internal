use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bitwarden_noise_protocol::MultiDeviceTransport;
use bitwarden_proxy::{IdentityFingerprint, IdentityKeyPair, IncomingMessage, RendevouzCode};
use bitwarden_rat_client::{
    IdentityProvider, ProxyClient, SessionStore, UserClient, UserClientEvent, UserClientResponse,
    UserCredentialData,
};
use bitwarden_threading::ThreadBoundRunner;
use tokio::sync::mpsc;
use wasm_bindgen::prelude::*;

// ---------- TypeScript interface definitions ----------

#[wasm_bindgen(typescript_custom_section)]
const RAT_SESSION_STORE_TS: &'static str = r#"
export interface RatSessionStore {
    has_session(fingerprint: string): Promise<boolean>;
    cache_session(fingerprint: string): Promise<void>;
    remove_session(fingerprint: string): Promise<void>;
    clear(): Promise<void>;
    list_sessions(): Promise<Array<{ fingerprint: string; name: string | null; lastConnected: number }>>;
    update_last_connected(fingerprint: string): Promise<void>;
    save_transport_state(fingerprint: string, state: Uint8Array): Promise<void>;
    load_transport_state(fingerprint: string): Promise<Uint8Array | null>;
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const RAT_PROXY_CLIENT_TS: &'static str = r#"
export interface RatProxyClient {
    connect(): Promise<void>;
    request_rendezvous(): Promise<void>;
    request_identity(code: string): Promise<void>;
    send_to(fingerprint: string, data: Uint8Array): Promise<void>;
    disconnect(): Promise<void>;
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const RAT_EVENT_HANDLER_TS: &'static str = r#"
export interface RatEventHandler {
    on_event(event: object): void;
}
"#;

// ---------- JS extern "C" type declarations ----------

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = RatSessionStore)]
    pub type JsSessionStore;

    #[wasm_bindgen(method)]
    async fn has_session(this: &JsSessionStore, fingerprint: &str) -> JsValue;

    #[wasm_bindgen(method)]
    async fn cache_session(this: &JsSessionStore, fingerprint: &str);

    #[wasm_bindgen(method)]
    async fn remove_session(this: &JsSessionStore, fingerprint: &str);

    #[wasm_bindgen(method)]
    async fn clear(this: &JsSessionStore);

    #[wasm_bindgen(method)]
    async fn list_sessions(this: &JsSessionStore) -> JsValue;

    #[wasm_bindgen(method)]
    async fn update_last_connected(this: &JsSessionStore, fingerprint: &str);

    #[wasm_bindgen(method)]
    async fn save_transport_state(this: &JsSessionStore, fingerprint: &str, state: &[u8]);

    #[wasm_bindgen(method)]
    async fn load_transport_state(this: &JsSessionStore, fingerprint: &str) -> JsValue;
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = RatProxyClient)]
    pub type JsProxyClient;

    #[wasm_bindgen(method)]
    async fn connect(this: &JsProxyClient);

    #[wasm_bindgen(method)]
    async fn request_rendezvous(this: &JsProxyClient);

    #[wasm_bindgen(method)]
    async fn request_identity(this: &JsProxyClient, code: &str);

    #[wasm_bindgen(method)]
    async fn send_to(this: &JsProxyClient, fingerprint: &str, data: &[u8]);

    #[wasm_bindgen(method)]
    async fn disconnect(this: &JsProxyClient);
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = RatEventHandler)]
    pub type JsEventHandler;

    #[wasm_bindgen(method)]
    fn on_event(this: &JsEventHandler, event: JsValue);
}

// ---------- Helper: fingerprint hex conversion ----------

fn fingerprint_to_hex(fp: &IdentityFingerprint) -> String {
    hex::encode(fp.0)
}

fn fingerprint_from_hex(hex_str: &str) -> Result<IdentityFingerprint, JsValue> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| JsValue::from_str(&format!("Invalid fingerprint hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(JsValue::from_str("Fingerprint must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(IdentityFingerprint(arr))
}

/// Parse a hex-encoded fingerprint string into an IdentityFingerprint.
/// Returns None if the hex is invalid or not 32 bytes.
fn parse_fingerprint_hex(hex_str: &str) -> Option<IdentityFingerprint> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(IdentityFingerprint(arr))
}

// ---------- WasmIdentityProvider ----------

struct WasmIdentityProvider {
    keypair: IdentityKeyPair,
}

impl WasmIdentityProvider {
    fn new(cose_bytes: &[u8]) -> Result<Self, JsValue> {
        let keypair = IdentityKeyPair::from_cose(cose_bytes)
            .map_err(|_| JsValue::from_str("Failed to parse COSE identity keypair"))?;
        Ok(Self { keypair })
    }
}

impl IdentityProvider for WasmIdentityProvider {
    fn identity(&self) -> &IdentityKeyPair {
        &self.keypair
    }
}

// ---------- WasmSessionStore ----------

struct WasmSessionStore {
    runner: ThreadBoundRunner<JsSessionStore>,
}

#[async_trait]
impl SessionStore for WasmSessionStore {
    async fn has_session(&self, fingerprint: &IdentityFingerprint) -> bool {
        let fp_hex = fingerprint_to_hex(fingerprint);
        self.runner
            .run_in_thread(move |js| async move {
                js.has_session(&fp_hex).await.as_bool().unwrap_or(false)
            })
            .await
            .unwrap_or(false)
    }

    async fn cache_session(
        &mut self,
        fingerprint: IdentityFingerprint,
    ) -> Result<(), bitwarden_rat_client::RemoteClientError> {
        let fp_hex = fingerprint_to_hex(&fingerprint);
        self.runner
            .run_in_thread(move |js| async move {
                js.cache_session(&fp_hex).await;
            })
            .await
            .map_err(|e| {
                bitwarden_rat_client::RemoteClientError::SessionCache(e.to_string())
            })
    }

    async fn remove_session(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), bitwarden_rat_client::RemoteClientError> {
        let fp_hex = fingerprint_to_hex(fingerprint);
        self.runner
            .run_in_thread(move |js| async move {
                js.remove_session(&fp_hex).await;
            })
            .await
            .map_err(|e| {
                bitwarden_rat_client::RemoteClientError::SessionCache(e.to_string())
            })
    }

    async fn clear(&mut self) -> Result<(), bitwarden_rat_client::RemoteClientError> {
        self.runner
            .run_in_thread(move |js| async move {
                js.clear().await;
            })
            .await
            .map_err(|e| {
                bitwarden_rat_client::RemoteClientError::SessionCache(e.to_string())
            })
    }

    async fn list_sessions(&self) -> Vec<(IdentityFingerprint, Option<String>, u64)> {
        // Extract raw data (String-based) from JS inside the thread-bound closure,
        // then convert fingerprint hex strings to IdentityFingerprint outside.
        let raw: Vec<(String, Option<String>, u64)> = self
            .runner
            .run_in_thread(move |js| async move {
                let js_result = js.list_sessions().await;

                // Parse the JS array of { fingerprint, name, lastConnected }
                let array: js_sys::Array = match js_result.dyn_into() {
                    Ok(a) => a,
                    Err(_) => return Vec::new(),
                };

                let mut sessions = Vec::new();
                for i in 0..array.length() {
                    let entry = array.get(i);
                    let fp_val =
                        js_sys::Reflect::get(&entry, &JsValue::from_str("fingerprint")).ok();
                    let name_val =
                        js_sys::Reflect::get(&entry, &JsValue::from_str("name")).ok();
                    let last_val =
                        js_sys::Reflect::get(&entry, &JsValue::from_str("lastConnected")).ok();

                    if let Some(fp_str) = fp_val.and_then(|v| v.as_string()) {
                        let name = name_val.and_then(|v| v.as_string());
                        let last_connected =
                            last_val.and_then(|v| v.as_f64()).unwrap_or(0.0) as u64;
                        sessions.push((fp_str, name, last_connected));
                    }
                }
                sessions
            })
            .await
            .unwrap_or_default();

        raw.into_iter()
            .filter_map(|(fp_hex, name, last_connected)| {
                parse_fingerprint_hex(&fp_hex).map(|fp| (fp, name, last_connected))
            })
            .collect()
    }

    async fn update_last_connected(
        &mut self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), bitwarden_rat_client::RemoteClientError> {
        let fp_hex = fingerprint_to_hex(fingerprint);
        self.runner
            .run_in_thread(move |js| async move {
                js.update_last_connected(&fp_hex).await;
            })
            .await
            .map_err(|e| {
                bitwarden_rat_client::RemoteClientError::SessionCache(e.to_string())
            })
    }

    async fn save_transport_state(
        &mut self,
        fingerprint: &IdentityFingerprint,
        transport_state: MultiDeviceTransport,
    ) -> Result<(), bitwarden_rat_client::RemoteClientError> {
        let fp_hex = fingerprint_to_hex(fingerprint);
        let bytes = transport_state.save_state().map_err(|e| {
            bitwarden_rat_client::RemoteClientError::Serialization(format!(
                "Failed to serialize transport state: {e}"
            ))
        })?;
        self.runner
            .run_in_thread(move |js| async move {
                js.save_transport_state(&fp_hex, &bytes).await;
            })
            .await
            .map_err(|e| {
                bitwarden_rat_client::RemoteClientError::SessionCache(e.to_string())
            })
    }

    async fn load_transport_state(
        &self,
        fingerprint: &IdentityFingerprint,
    ) -> Result<Option<MultiDeviceTransport>, bitwarden_rat_client::RemoteClientError> {
        let fp_hex = fingerprint_to_hex(fingerprint);
        // Extract raw bytes from JS inside the thread-bound closure, returning
        // Option<Vec<u8>> which is Send + Sync.
        let bytes = self
            .runner
            .run_in_thread(move |js| async move {
                let js_result = js.load_transport_state(&fp_hex).await;

                if js_result.is_null() || js_result.is_undefined() {
                    return Ok(None);
                }

                let uint8array: js_sys::Uint8Array =
                    js_result.dyn_into().map_err(|_| {
                        "Expected Uint8Array from load_transport_state".to_string()
                    })?;
                Ok(Some(uint8array.to_vec()))
            })
            .await
            .map_err(|e| {
                bitwarden_rat_client::RemoteClientError::SessionCache(e.to_string())
            })?
            .map_err(|e: String| {
                bitwarden_rat_client::RemoteClientError::Serialization(e)
            })?;

        match bytes {
            None => Ok(None),
            Some(bytes) => {
                let transport =
                    MultiDeviceTransport::restore_state(&bytes).map_err(|e| {
                        bitwarden_rat_client::RemoteClientError::Serialization(format!(
                            "Failed to deserialize transport state: {e}"
                        ))
                    })?;
                Ok(Some(transport))
            }
        }
    }
}

// ---------- WasmProxyClient ----------

struct WasmProxyClient {
    runner: ThreadBoundRunner<JsProxyClient>,
    incoming_tx: Arc<Mutex<Option<mpsc::UnboundedSender<IncomingMessage>>>>,
}

#[async_trait::async_trait]
impl ProxyClient for WasmProxyClient {
    async fn connect(
        &mut self,
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, bitwarden_rat_client::RemoteClientError>
    {
        self.runner
            .run_in_thread(|c| async move {
                c.connect().await;
            })
            .await
            .map_err(|e| {
                bitwarden_rat_client::RemoteClientError::ConnectionFailed(e.to_string())
            })?;

        let (tx, rx) = mpsc::unbounded_channel();
        *self.incoming_tx.lock().expect("mutex poisoned") = Some(tx);
        Ok(rx)
    }

    async fn request_rendezvous(&self) -> Result<(), bitwarden_rat_client::RemoteClientError> {
        self.runner
            .run_in_thread(|c| async move {
                c.request_rendezvous().await;
            })
            .await
            .map_err(|e| {
                bitwarden_rat_client::RemoteClientError::ConnectionFailed(e.to_string())
            })
    }

    async fn request_identity(
        &self,
        code: RendevouzCode,
    ) -> Result<(), bitwarden_rat_client::RemoteClientError> {
        let code_str = code.as_str().to_string();
        self.runner
            .run_in_thread(move |c| async move {
                c.request_identity(&code_str).await;
            })
            .await
            .map_err(|e| {
                bitwarden_rat_client::RemoteClientError::ConnectionFailed(e.to_string())
            })
    }

    async fn send_to(
        &self,
        fingerprint: IdentityFingerprint,
        data: Vec<u8>,
    ) -> Result<(), bitwarden_rat_client::RemoteClientError> {
        let fp_hex = fingerprint_to_hex(&fingerprint);
        self.runner
            .run_in_thread(move |c| async move {
                c.send_to(&fp_hex, &data).await;
            })
            .await
            .map_err(|e| {
                bitwarden_rat_client::RemoteClientError::ConnectionFailed(e.to_string())
            })
    }

    async fn disconnect(&mut self) -> Result<(), bitwarden_rat_client::RemoteClientError> {
        self.runner
            .run_in_thread(|c| async move {
                c.disconnect().await;
            })
            .await
            .map_err(|e| {
                bitwarden_rat_client::RemoteClientError::ConnectionFailed(e.to_string())
            })
    }
}

// ---------- WasmUserClient ----------

#[wasm_bindgen]
pub struct WasmUserClient {
    inner: Option<UserClient>,
    incoming_tx: Arc<Mutex<Option<mpsc::UnboundedSender<IncomingMessage>>>>,
    response_tx: Option<mpsc::Sender<UserClientResponse>>,
}

#[wasm_bindgen]
impl WasmUserClient {
    /// Create a new WasmUserClient and connect to the proxy.
    ///
    /// `identity_cose_bytes` - COSE-encoded identity keypair bytes
    /// `session_store` - JS object implementing the RatSessionStore interface
    /// `proxy_client` - JS object implementing the RatProxyClient interface
    pub async fn create(
        identity_cose_bytes: Vec<u8>,
        session_store: JsSessionStore,
        proxy_client: JsProxyClient,
    ) -> Result<WasmUserClient, JsValue> {
        let identity_provider =
            Box::new(WasmIdentityProvider::new(&identity_cose_bytes)?) as Box<dyn IdentityProvider>;

        let wasm_session_store = Box::new(WasmSessionStore {
            runner: ThreadBoundRunner::new(session_store),
        }) as Box<dyn SessionStore>;

        let incoming_tx: Arc<Mutex<Option<mpsc::UnboundedSender<IncomingMessage>>>> =
            Arc::new(Mutex::new(None));

        let wasm_proxy_client = Box::new(WasmProxyClient {
            runner: ThreadBoundRunner::new(proxy_client),
            incoming_tx: Arc::clone(&incoming_tx),
        }) as Box<dyn ProxyClient>;

        let user_client =
            UserClient::listen(identity_provider, wasm_session_store, wasm_proxy_client)
                .await
                .map_err(|e| JsValue::from_str(&format!("Failed to listen: {e}")))?;

        Ok(WasmUserClient {
            inner: Some(user_client),
            incoming_tx,
            response_tx: None,
        })
    }

    /// Enable PSK mode and start the event loop.
    ///
    /// Events will be forwarded to the provided event handler's `on_event` callback.
    pub fn enable_psk(&mut self, event_handler: JsEventHandler) -> Result<(), JsValue> {
        let mut client = self
            .inner
            .take()
            .ok_or_else(|| JsValue::from_str("Client already consumed"))?;

        let (event_tx, mut event_rx) = mpsc::channel::<UserClientEvent>(32);
        let (response_tx, response_rx) = mpsc::channel::<UserClientResponse>(32);
        self.response_tx = Some(response_tx);

        // Spawn the event forwarding loop
        wasm_bindgen_futures::spawn_local(async move {
            while let Some(event) = event_rx.recv().await {
                let js_val = serde_wasm_bindgen::to_value(&event).unwrap_or(JsValue::NULL);
                event_handler.on_event(js_val);
            }
        });

        // Spawn the main client event loop
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = client.enable_psk(event_tx, response_rx).await {
                tracing::error!("PSK event loop error: {e}");
            }
        });

        Ok(())
    }

    /// Enable rendezvous mode and start the event loop.
    ///
    /// Events will be forwarded to the provided event handler's `on_event` callback.
    pub fn enable_rendezvous(&mut self, event_handler: JsEventHandler) -> Result<(), JsValue> {
        let mut client = self
            .inner
            .take()
            .ok_or_else(|| JsValue::from_str("Client already consumed"))?;

        let (event_tx, mut event_rx) = mpsc::channel::<UserClientEvent>(32);
        let (response_tx, response_rx) = mpsc::channel::<UserClientResponse>(32);
        self.response_tx = Some(response_tx);

        // Spawn the event forwarding loop
        wasm_bindgen_futures::spawn_local(async move {
            while let Some(event) = event_rx.recv().await {
                let js_val = serde_wasm_bindgen::to_value(&event).unwrap_or(JsValue::NULL);
                event_handler.on_event(js_val);
            }
        });

        // Spawn the main client event loop
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = client.enable_rendezvous(event_tx, response_rx).await {
                tracing::error!("Rendezvous event loop error: {e}");
            }
        });

        Ok(())
    }

    /// Push an incoming Send message from JS (WebSocket relay).
    ///
    /// `source_hex` - hex-encoded source fingerprint
    /// `dest_hex` - hex-encoded destination fingerprint
    /// `payload` - message payload bytes
    pub fn push_incoming_message(
        &self,
        source_hex: String,
        dest_hex: String,
        payload: Vec<u8>,
    ) -> Result<(), JsValue> {
        let source = fingerprint_from_hex(&source_hex)?;
        let destination = fingerprint_from_hex(&dest_hex)?;

        let guard = self.incoming_tx.lock().expect("mutex poisoned");
        if let Some(tx) = guard.as_ref() {
            tx.send(IncomingMessage::Send {
                source,
                destination,
                payload,
            })
            .map_err(|_| JsValue::from_str("Incoming channel closed"))?;
        } else {
            return Err(JsValue::from_str("Not connected - incoming channel not set"));
        }
        Ok(())
    }

    /// Push an incoming rendezvous info message from JS.
    ///
    /// `code` - the rendezvous code string
    pub fn push_incoming_rendezvous(&self, code: String) -> Result<(), JsValue> {
        let guard = self.incoming_tx.lock().expect("mutex poisoned");
        if let Some(tx) = guard.as_ref() {
            tx.send(IncomingMessage::RendevouzInfo(
                RendevouzCode::from_string(code),
            ))
            .map_err(|_| JsValue::from_str("Incoming channel closed"))?;
        } else {
            return Err(JsValue::from_str("Not connected - incoming channel not set"));
        }
        Ok(())
    }

    /// Push an incoming identity info message from JS.
    ///
    /// `fingerprint_hex` - hex-encoded fingerprint
    /// `identity_cose` - COSE-encoded public identity bytes
    pub fn push_incoming_identity(
        &self,
        fingerprint_hex: String,
        identity_cose: Vec<u8>,
    ) -> Result<(), JsValue> {
        let fingerprint = fingerprint_from_hex(&fingerprint_hex)?;

        // Reconstruct the Identity from COSE bytes by creating a temporary keypair
        // and extracting the public identity. However, IdentityInfo expects an Identity,
        // which is the public part. We need to parse COSE public key bytes.
        // The Identity struct has a cose_key_bytes field, but it's not directly constructable.
        // We use the IdentityKeyPair::from_cose to get the public identity.
        let keypair = IdentityKeyPair::from_cose(&identity_cose)
            .map_err(|_| JsValue::from_str("Failed to parse identity COSE bytes"))?;
        let identity = keypair.identity();

        let guard = self.incoming_tx.lock().expect("mutex poisoned");
        if let Some(tx) = guard.as_ref() {
            tx.send(IncomingMessage::IdentityInfo {
                fingerprint,
                identity,
            })
            .map_err(|_| JsValue::from_str("Incoming channel closed"))?;
        } else {
            return Err(JsValue::from_str("Not connected - incoming channel not set"));
        }
        Ok(())
    }

    /// Respond to a credential request.
    ///
    /// `request_id` - the request ID from the CredentialRequest event
    /// `session_id` - the session ID from the CredentialRequest event
    /// `approved` - whether to approve or deny the request
    /// `credential` - optional credential data (JSON object) if approved
    pub async fn respond_credential(
        &self,
        request_id: String,
        session_id: String,
        approved: bool,
        credential: JsValue,
    ) -> Result<(), JsValue> {
        let credential_data: Option<UserCredentialData> = if approved && !credential.is_null() && !credential.is_undefined() {
            Some(
                serde_wasm_bindgen::from_value(credential)
                    .map_err(|e| JsValue::from_str(&format!("Invalid credential data: {e}")))?,
            )
        } else {
            None
        };

        let response = UserClientResponse::RespondCredential {
            request_id,
            session_id,
            approved,
            credential: credential_data,
        };

        if let Some(tx) = &self.response_tx {
            tx.send(response)
                .await
                .map_err(|_| JsValue::from_str("Response channel closed"))?;
        } else {
            return Err(JsValue::from_str(
                "No response channel - call enable_psk or enable_rendezvous first",
            ));
        }

        Ok(())
    }
}
