//! WASM-exposed `RatUserClient` wrapping `bw_rat_client::UserClient`.

use std::{
    cell::RefCell,
    sync::{Arc, Mutex},
};

use bw_rat_client::{
    IdentityKeyPair, Messages, SessionStore, UserClient, UserClientEvent, UserClientResponse,
};
use tokio::sync::mpsc;
use wasm_bindgen::prelude::*;

use super::{
    proxy::{JsRatProxyClient, WasmProxyClient},
    storage::{InMemoryIdentityProvider, InMemorySessionStore},
};

// TypeScript type definitions for events and responses
#[wasm_bindgen(typescript_custom_section)]
const RAT_TS_TYPES: &'static str = r#"
export type RatUserClientEvent =
    | { type: "listening" }
    | { type: "rendezvous_code_generated"; code: string }
    | { type: "psk_token_generated"; token: string }
    | { type: "handshake_start" }
    | { type: "handshake_progress"; message: string }
    | { type: "handshake_complete" }
    | { type: "handshake_fingerprint"; fingerprint: string }
    | { type: "fingerprint_verified" }
    | { type: "fingerprint_rejected"; reason: string }
    | { type: "credential_request"; domain: string; request_id: string; session_id: string }
    | { type: "credential_approved"; domain: string }
    | { type: "credential_denied"; domain: string }
    | { type: "session_refreshed"; fingerprint: string }
    | { type: "client_disconnected" }
    | { type: "error"; message: string; context?: string };

export type RatUserClientResponse =
    | { type: "verify_fingerprint"; approved: boolean; name?: string }
    | { type: "respond_credential"; request_id: string; session_id: string; approved: boolean; credential?: RatCredentialData };

export interface RatCredentialData {
    username?: string;
    password?: string;
    totp?: string;
    uri?: string;
    notes?: string;
}

/**
 * Static helper for proxy authentication.
 * Call `RatUserClient.sign_proxy_challenge(identityCose, challengeJson)`
 * to sign the proxy server's auth challenge without exposing key material to JS.
 */
"#;

/// Shared session store wrapper that implements SessionStore by delegating
/// to an inner `Arc<Mutex<InMemorySessionStore>>`.
struct SharedSessionStore(Arc<Mutex<InMemorySessionStore>>);

impl SessionStore for SharedSessionStore {
    fn has_session(&self, fingerprint: &bw_rat_client::IdentityFingerprint) -> bool {
        self.0
            .lock()
            .expect("lock poisoned")
            .has_session(fingerprint)
    }

    fn cache_session(
        &mut self,
        fingerprint: bw_rat_client::IdentityFingerprint,
    ) -> Result<(), bw_rat_client::RemoteClientError> {
        self.0
            .lock()
            .expect("lock poisoned")
            .cache_session(fingerprint)
    }

    fn remove_session(
        &mut self,
        fingerprint: &bw_rat_client::IdentityFingerprint,
    ) -> Result<(), bw_rat_client::RemoteClientError> {
        self.0
            .lock()
            .expect("lock poisoned")
            .remove_session(fingerprint)
    }

    fn clear(&mut self) -> Result<(), bw_rat_client::RemoteClientError> {
        self.0.lock().expect("lock poisoned").clear()
    }

    fn list_sessions(&self) -> Vec<(bw_rat_client::IdentityFingerprint, Option<String>, u64, u64)> {
        self.0.lock().expect("lock poisoned").list_sessions()
    }

    fn set_session_name(
        &mut self,
        fingerprint: &bw_rat_client::IdentityFingerprint,
        name: String,
    ) -> Result<(), bw_rat_client::RemoteClientError> {
        self.0
            .lock()
            .expect("lock poisoned")
            .set_session_name(fingerprint, name)
    }

    fn update_last_connected(
        &mut self,
        fingerprint: &bw_rat_client::IdentityFingerprint,
    ) -> Result<(), bw_rat_client::RemoteClientError> {
        self.0
            .lock()
            .expect("lock poisoned")
            .update_last_connected(fingerprint)
    }

    fn save_transport_state(
        &mut self,
        fingerprint: &bw_rat_client::IdentityFingerprint,
        transport_state: bw_rat_client::MultiDeviceTransport,
    ) -> Result<(), bw_rat_client::RemoteClientError> {
        self.0
            .lock()
            .expect("lock poisoned")
            .save_transport_state(fingerprint, transport_state)
    }

    fn load_transport_state(
        &self,
        fingerprint: &bw_rat_client::IdentityFingerprint,
    ) -> Result<Option<bw_rat_client::MultiDeviceTransport>, bw_rat_client::RemoteClientError> {
        self.0
            .lock()
            .expect("lock poisoned")
            .load_transport_state(fingerprint)
    }
}

/// WASM-exposed Remote Access Token (RAT) UserClient.
///
/// This is the trusted device side that serves credentials to requesting devices.
#[wasm_bindgen]
pub struct RatUserClient {
    client: RefCell<Option<UserClient>>,
    session_data: Arc<Mutex<InMemorySessionStore>>,
    identity: Vec<u8>,
    response_tx: RefCell<Option<mpsc::Sender<UserClientResponse>>>,
}

#[wasm_bindgen]
impl RatUserClient {
    /// Create and connect a new UserClient.
    ///
    /// - `proxy_client`: JavaScript implementation of the `RatProxyClient` interface
    /// - `initial_session_data`: Optional JSON string of previously persisted session data
    /// - `initial_identity_data`: Optional COSE-encoded identity keypair bytes
    pub async fn listen(
        proxy_client: JsRatProxyClient,
        initial_session_data: Option<String>,
        initial_identity_data: Option<Vec<u8>>,
    ) -> Result<RatUserClient, JsValue> {
        // Create session store
        let session_store = match initial_session_data {
            Some(ref data) if !data.is_empty() => InMemorySessionStore::from_json(data)
                .map_err(|e| JsValue::from_str(&format!("Invalid session data: {e}")))?,
            _ => InMemorySessionStore::new(),
        };
        let session_arc = Arc::new(Mutex::new(session_store));
        let shared_store = SharedSessionStore(session_arc.clone());

        // Create identity provider
        let identity = match initial_identity_data {
            Some(ref data) if !data.is_empty() => InMemoryIdentityProvider::from_bytes(data)
                .map_err(|e| JsValue::from_str(&format!("Invalid identity data: {e}")))?,
            _ => InMemoryIdentityProvider::generate(),
        };
        let identity_bytes = identity.to_bytes();

        // Create proxy client wrapper
        let proxy = WasmProxyClient::new(proxy_client);

        // Create the client
        let client =
            UserClient::listen(Box::new(identity), Box::new(shared_store), Box::new(proxy))
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(RatUserClient {
            client: RefCell::new(Some(client)),
            session_data: session_arc,
            identity: identity_bytes,
            response_tx: RefCell::new(None),
        })
    }

    /// Enable rendezvous mode: generates a pairing code and runs the event loop.
    ///
    /// The `event_callback` is called for each event. Returns when the client disconnects.
    pub async fn enable_rendezvous(&self, event_callback: js_sys::Function) -> Result<(), JsValue> {
        let mut client = self
            .client
            .borrow_mut()
            .take()
            .ok_or_else(|| JsValue::from_str("Client not initialized"))?;

        let (event_tx, event_rx) = mpsc::channel(32);
        let (response_tx, response_rx) = mpsc::channel(32);
        *self.response_tx.borrow_mut() = Some(response_tx);

        // Forward events to JS
        Self::spawn_event_forwarder(event_rx, event_callback);

        // RefCell borrow is released here — client is owned locally.
        // This allows send_response(&self) to be called concurrently.
        let result = client
            .enable_rendezvous(event_tx, response_rx)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()));

        // Put client back
        *self.client.borrow_mut() = Some(client);
        result
    }

    /// Enable PSK mode: generates a PSK token and runs the event loop.
    pub async fn enable_psk(&self, event_callback: js_sys::Function) -> Result<(), JsValue> {
        let mut client = self
            .client
            .borrow_mut()
            .take()
            .ok_or_else(|| JsValue::from_str("Client not initialized"))?;

        let (event_tx, event_rx) = mpsc::channel(32);
        let (response_tx, response_rx) = mpsc::channel(32);
        *self.response_tx.borrow_mut() = Some(response_tx);

        Self::spawn_event_forwarder(event_rx, event_callback);

        let result = client
            .enable_psk(event_tx, response_rx)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()));

        *self.client.borrow_mut() = Some(client);
        result
    }

    /// Listen for cached sessions only (no new pairing).
    pub async fn listen_cached_only(
        &self,
        event_callback: js_sys::Function,
    ) -> Result<(), JsValue> {
        let mut client = self
            .client
            .borrow_mut()
            .take()
            .ok_or_else(|| JsValue::from_str("Client not initialized"))?;

        let (event_tx, event_rx) = mpsc::channel(32);
        let (response_tx, response_rx) = mpsc::channel(32);
        *self.response_tx.borrow_mut() = Some(response_tx);

        Self::spawn_event_forwarder(event_rx, event_callback);

        let result = client
            .listen_cached_only(event_tx, response_rx)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()));

        *self.client.borrow_mut() = Some(client);
        result
    }

    /// Send a response to a pending event (fingerprint verification or credential request).
    pub fn send_response(&self, response: JsValue) -> Result<(), JsValue> {
        let tx_ref = self.response_tx.borrow();
        let tx = tx_ref
            .as_ref()
            .ok_or_else(|| JsValue::from_str("No active event loop"))?;

        let parsed: serde_json::Value = tsify::serde_wasm_bindgen::from_value(response)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let response = parse_user_response(&parsed).map_err(|e| JsValue::from_str(&e))?;

        tx.try_send(response)
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Get the current rendezvous code (if in rendezvous mode).
    pub fn get_rendezvous_code(&self) -> Option<String> {
        self.client
            .borrow()
            .as_ref()
            .and_then(|c| c.rendezvous_code().map(|code| code.as_str().to_string()))
    }

    /// Set a friendly name for the next newly-paired session.
    pub fn set_pending_session_name(&self, name: String) {
        if let Some(client) = self.client.borrow_mut().as_mut() {
            client.set_pending_session_name(name);
        }
    }

    /// Get serialized session data for persistence to `chrome.storage.local`.
    pub fn get_session_data(&self) -> Result<String, JsValue> {
        self.session_data
            .lock()
            .expect("lock poisoned")
            .to_json()
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Get serialized identity data for persistence to `chrome.storage.local`.
    pub fn get_identity_data(&self) -> Vec<u8> {
        self.identity.clone()
    }

    /// Generate a new random identity keypair, returned as COSE-encoded bytes.
    ///
    /// Use this to create an identity before calling `listen()`, so the proxy
    /// client has valid identity bytes for the auth challenge-response.
    pub fn generate_identity() -> Vec<u8> {
        InMemoryIdentityProvider::generate().to_bytes()
    }

    /// Sign a proxy authentication challenge.
    ///
    /// Takes the challenge JSON from the proxy server and the COSE-encoded identity keypair.
    /// Returns the auth response JSON to send back to the proxy.
    ///
    /// This is used by the JavaScript `RatProxyClient` implementation to complete
    /// the proxy authentication handshake without exposing key material to JS.
    pub fn sign_proxy_challenge(
        identity_cose: Vec<u8>,
        challenge_json: String,
    ) -> Result<String, JsValue> {
        let keypair = IdentityKeyPair::from_cose(&identity_cose)
            .map_err(|e| JsValue::from_str(&format!("Invalid identity: {e}")))?;

        let messages: Messages = serde_json::from_str(&challenge_json)
            .map_err(|e| JsValue::from_str(&format!("Invalid challenge JSON: {e}")))?;

        let challenge = match messages {
            Messages::AuthChallenge(c) => c,
            _ => return Err(JsValue::from_str("Expected AuthChallenge message")),
        };

        let response = challenge.sign(&keypair);
        let auth_response = Messages::AuthResponse(keypair.identity(), response);

        serde_json::to_string(&auth_response)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
    }
}

impl RatUserClient {
    /// Spawn a task that reads events from the channel and forwards them to JS.
    fn spawn_event_forwarder(
        mut event_rx: mpsc::Receiver<UserClientEvent>,
        callback: js_sys::Function,
    ) {
        wasm_bindgen_futures::spawn_local(async move {
            tracing::info!("Event forwarder task started");
            while let Some(event) = event_rx.recv().await {
                tracing::info!("Event forwarder: forwarding event: {event:?}");
                let js_event = event_to_js(&event);
                match js_event {
                    Ok(val) => {
                        let _ = callback.call1(&JsValue::NULL, &val);
                    }
                    Err(e) => {
                        tracing::warn!("Event forwarder: failed to convert event: {e:?}");
                    }
                }
            }
            tracing::info!("Event forwarder task ended");
        });
    }
}

/// Convert a `UserClientEvent` to a JS object.
fn event_to_js(event: &UserClientEvent) -> Result<JsValue, JsValue> {
    let json = match event {
        UserClientEvent::Listening {} => {
            serde_json::json!({ "type": "listening" })
        }
        UserClientEvent::RendevouzCodeGenerated { code } => {
            serde_json::json!({ "type": "rendezvous_code_generated", "code": code })
        }
        UserClientEvent::PskTokenGenerated { token } => {
            serde_json::json!({ "type": "psk_token_generated", "token": token })
        }
        UserClientEvent::HandshakeStart {} => {
            serde_json::json!({ "type": "handshake_start" })
        }
        UserClientEvent::HandshakeProgress { message } => {
            serde_json::json!({ "type": "handshake_progress", "message": message })
        }
        UserClientEvent::HandshakeComplete {} => {
            serde_json::json!({ "type": "handshake_complete" })
        }
        UserClientEvent::HandshakeFingerprint { fingerprint } => {
            serde_json::json!({ "type": "handshake_fingerprint", "fingerprint": fingerprint })
        }
        UserClientEvent::FingerprintVerified {} => {
            serde_json::json!({ "type": "fingerprint_verified" })
        }
        UserClientEvent::FingerprintRejected { reason } => {
            serde_json::json!({ "type": "fingerprint_rejected", "reason": reason })
        }
        UserClientEvent::CredentialRequest {
            domain,
            request_id,
            session_id,
        } => {
            serde_json::json!({
                "type": "credential_request",
                "domain": domain,
                "request_id": request_id,
                "session_id": session_id,
            })
        }
        UserClientEvent::CredentialApproved { domain } => {
            serde_json::json!({ "type": "credential_approved", "domain": domain })
        }
        UserClientEvent::CredentialDenied { domain } => {
            serde_json::json!({ "type": "credential_denied", "domain": domain })
        }
        UserClientEvent::SessionRefreshed { fingerprint } => {
            serde_json::json!({ "type": "session_refreshed", "fingerprint": format!("{fingerprint:?}") })
        }
        UserClientEvent::ClientDisconnected {} => {
            serde_json::json!({ "type": "client_disconnected" })
        }
        UserClientEvent::Error { message, context } => {
            serde_json::json!({ "type": "error", "message": message, "context": context })
        }
    };

    let serializer = tsify::serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    serde::Serialize::serialize(&json, &serializer).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Parse a JS response object into `UserClientResponse`.
fn parse_user_response(parsed: &serde_json::Value) -> Result<UserClientResponse, String> {
    let resp_type = parsed["type"].as_str().ok_or("missing type")?;

    match resp_type {
        "verify_fingerprint" => {
            let approved = parsed["approved"].as_bool().ok_or("missing approved")?;
            let name = parsed["name"].as_str().map(|s| s.to_string());
            Ok(UserClientResponse::VerifyFingerprint { approved, name })
        }
        "respond_credential" => {
            let request_id = parsed["request_id"]
                .as_str()
                .ok_or("missing request_id")?
                .to_string();
            let session_id = parsed["session_id"]
                .as_str()
                .ok_or("missing session_id")?
                .to_string();
            let approved = parsed["approved"].as_bool().ok_or("missing approved")?;
            let credential = if approved {
                parsed.get("credential").and_then(|c| {
                    serde_json::from_value::<bw_rat_client::UserCredentialData>(c.clone()).ok()
                })
            } else {
                None
            };
            Ok(UserClientResponse::RespondCredential {
                request_id,
                session_id,
                approved,
                credential,
            })
        }
        _ => Err(format!("Unknown response type: {resp_type}")),
    }
}
