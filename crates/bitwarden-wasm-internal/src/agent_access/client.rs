//! WASM-exposed `UserClient` wrapping `ap_client::UserClient`.

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    rc::Rc,
    sync::Arc,
};

use ap_client::{
    AuditConnectionType, AuditEvent, AuditLog, CredentialRequestReply,
    FingerprintVerificationReply, UserClient as SdkUserClient, UserClientHandle,
    UserClientNotification, UserClientRequest,
};
use ap_proxy_protocol::{IdentityKeyPair, Messages};
use async_trait::async_trait;
use bitwarden_state::repository::Repository;
use tokio::sync::oneshot;
use wasm_bindgen::prelude::*;

use super::{
    proxy::{JsProxyClient, WasmProxyClient},
    storage::{
        ConnectionRecord, InMemoryIdentityProvider, PskRecord, RepositoryConnectionStore,
        RepositoryPskStore,
    },
};
use crate::platform::repository::{WasmRepository, WasmRepositoryChannel};

/// Tracks the oneshot reply channel for a pending request forwarded to JS.
enum PendingReplyKind {
    Fingerprint(oneshot::Sender<FingerprintVerificationReply>),
    Credential(oneshot::Sender<CredentialRequestReply>),
}

// TypeScript type definitions for events and responses
#[wasm_bindgen(typescript_custom_section)]
const TS_TYPES: &'static str = r#"
export type CredentialQuery =
    | { domain: string }
    | { id: string }
    | { search: string };

export type UserClientEvent =
    | { type: "listening" }
    | { type: "handshake_start" }
    | { type: "handshake_progress"; message: string }
    | { type: "handshake_complete" }
    | { type: "handshake_fingerprint"; fingerprint: string; identity: string }
    | { type: "fingerprint_verified" }
    | { type: "fingerprint_rejected"; reason: string }
    | { type: "verify_fingerprint_request"; fingerprint: string; identity: string; request_id: string }
    | { type: "credential_request"; query: CredentialQuery; identity: string; request_id: string }
    | { type: "credential_approved"; domain?: string; credential_id?: string }
    | { type: "credential_denied"; domain?: string; credential_id?: string }
    | { type: "session_refreshed"; fingerprint: string }
    | { type: "client_disconnected" }
    | { type: "reconnecting"; attempt: number }
    | { type: "reconnected" }
    | { type: "error"; message: string; context?: string };

export type UserClientResponse =
    | { type: "verify_fingerprint"; request_id: string; approved: boolean; name?: string }
    | { type: "respond_credential"; request_id: string; approved: boolean; credential?: CredentialData; credential_id?: string };

export interface CredentialData {
    username?: string;
    password?: string;
    totp?: string;
    uri?: string;
    notes?: string;
    credentialId?: string;
    domain?: string;
}

export type AuditLogEvent =
    | { type: "connection_established"; remoteIdentity: string; remoteName?: string; connectionType: "rendezvous" | "psk" }
    | { type: "session_refreshed"; remoteIdentity: string }
    | { type: "connection_rejected"; remoteIdentity: string }
    | { type: "credential_requested"; remoteIdentity: string; requestId: string; query: CredentialQuery }
    | { type: "credential_approved"; remoteIdentity: string; requestId: string; domain?: string; credentialId?: string; fields: string[] }
    | { type: "credential_denied"; remoteIdentity: string; requestId: string; domain?: string; credentialId?: string };

/**
 * ConnectionRecord stored in the connection repository.
 * The repository key is the hex-encoded identity fingerprint.
 */
export interface ConnectionRecord {
    fingerprint: number[];
    name: string | null;
    cachedAt: number;
    lastConnectedAt: number;
    transportState: number[] | null;
}

/**
 * PskRecord stored in the PSK repository.
 * The repository key is the psk_id string.
 */
export interface PskRecord {
    pskId: string;
    pskHex: string;
    name: string | null;
    createdAt: number;
}

/**
 * Static helper for proxy authentication.
 * Call `UserClient.sign_proxy_challenge(identityCose, challengeJson)`
 * to sign the proxy server's auth challenge without exposing key material to JS.
 */
"#;

// ---------------------------------------------------------------------------
// JsConnectionRepository — JS-provided Repository<ConnectionRecord>
// ---------------------------------------------------------------------------

#[wasm_bindgen]
extern "C" {
    /// JavaScript-provided connection repository implementing `Repository<ConnectionRecord>`.
    #[wasm_bindgen(js_name = ConnectionRepository)]
    pub type JsConnectionRepository;

    #[wasm_bindgen(method, catch)]
    async fn get(this: &JsConnectionRepository, id: String) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    async fn list(this: &JsConnectionRepository) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    async fn set(
        this: &JsConnectionRepository,
        id: String,
        value: JsValue,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "setBulk")]
    async fn set_bulk(this: &JsConnectionRepository, values: JsValue) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    async fn remove(this: &JsConnectionRepository, id: String) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "removeBulk")]
    async fn remove_bulk(this: &JsConnectionRepository, keys: JsValue) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "removeAll")]
    async fn remove_all(this: &JsConnectionRepository) -> Result<JsValue, JsValue>;
}

// ---------------------------------------------------------------------------
// JsPskRepository — JS-provided Repository<PskRecord>
// ---------------------------------------------------------------------------

#[wasm_bindgen]
extern "C" {
    /// JavaScript-provided PSK repository implementing `Repository<PskRecord>`.
    #[wasm_bindgen(js_name = PskRepository)]
    pub type JsPskRepository;

    #[wasm_bindgen(method, catch)]
    async fn get(this: &JsPskRepository, id: String) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    async fn list(this: &JsPskRepository) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    async fn set(this: &JsPskRepository, id: String, value: JsValue) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "setBulk")]
    async fn set_bulk(this: &JsPskRepository, values: JsValue) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch)]
    async fn remove(this: &JsPskRepository, id: String) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "removeBulk")]
    async fn remove_bulk(this: &JsPskRepository, keys: JsValue) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(method, catch, js_name = "removeAll")]
    async fn remove_all(this: &JsPskRepository) -> Result<JsValue, JsValue>;
}

impl WasmRepository<PskRecord> for JsPskRepository {
    async fn get(&self, id: String) -> Result<JsValue, JsValue> {
        self.get(id).await
    }
    async fn list(&self) -> Result<JsValue, JsValue> {
        self.list().await
    }
    async fn set(&self, id: String, value: PskRecord) -> Result<JsValue, JsValue> {
        let js_val = tsify::serde_wasm_bindgen::to_value(&value)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        self.set(id, js_val).await
    }
    async fn set_bulk(&self, values: Vec<(String, PskRecord)>) -> Result<JsValue, JsValue> {
        let js_val = tsify::serde_wasm_bindgen::to_value(&values)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        self.set_bulk(js_val).await
    }
    async fn remove(&self, id: String) -> Result<JsValue, JsValue> {
        self.remove(id).await
    }
    async fn remove_bulk(&self, keys: Vec<String>) -> Result<JsValue, JsValue> {
        let js_val = tsify::serde_wasm_bindgen::to_value(&keys)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        self.remove_bulk(js_val).await
    }
    async fn remove_all(&self) -> Result<JsValue, JsValue> {
        self.remove_all().await
    }
}

impl WasmRepository<ConnectionRecord> for JsConnectionRepository {
    async fn get(&self, id: String) -> Result<JsValue, JsValue> {
        self.get(id).await
    }
    async fn list(&self) -> Result<JsValue, JsValue> {
        self.list().await
    }
    async fn set(&self, id: String, value: ConnectionRecord) -> Result<JsValue, JsValue> {
        let js_val = tsify::serde_wasm_bindgen::to_value(&value)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        self.set(id, js_val).await
    }
    async fn set_bulk(&self, values: Vec<(String, ConnectionRecord)>) -> Result<JsValue, JsValue> {
        let js_val = tsify::serde_wasm_bindgen::to_value(&values)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        self.set_bulk(js_val).await
    }
    async fn remove(&self, id: String) -> Result<JsValue, JsValue> {
        self.remove(id).await
    }
    async fn remove_bulk(&self, keys: Vec<String>) -> Result<JsValue, JsValue> {
        let js_val = tsify::serde_wasm_bindgen::to_value(&keys)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        self.remove_bulk(js_val).await
    }
    async fn remove_all(&self) -> Result<JsValue, JsValue> {
        self.remove_all().await
    }
}

// ---------------------------------------------------------------------------
// WASM audit logger
// ---------------------------------------------------------------------------

/// WASM audit logger that forwards events to a JavaScript callback function.
struct JsAuditLog {
    callback: js_sys::Function,
}

// SAFETY: WASM is single-threaded, so Send + Sync are trivially satisfied.
unsafe impl Send for JsAuditLog {}
unsafe impl Sync for JsAuditLog {}

#[async_trait]
impl AuditLog for JsAuditLog {
    async fn write(&self, event: AuditEvent<'_>) {
        match audit_event_to_js(&event) {
            Ok(val) => {
                if let Err(e) = self.callback.call1(&JsValue::NULL, &val) {
                    tracing::warn!("Audit log JS callback error: {e:?}");
                }
            }
            Err(e) => {
                tracing::warn!("Audit log: failed to convert event: {e:?}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// UserClient
// ---------------------------------------------------------------------------

/// WASM-exposed UserClient.
///
/// This is the trusted device side that serves credentials to requesting devices.
#[wasm_bindgen]
pub struct UserClient {
    client: RefCell<Option<SdkUserClient>>,
    identity: Vec<u8>,
    /// Holds the identity provider between `new()` and `connect()`.
    identity_provider: RefCell<Option<InMemoryIdentityProvider>>,
    /// Holds the connection repository between `new()` and `connect()`.
    connection_repo: RefCell<Option<JsConnectionRepository>>,
    /// Holds the optional PSK repository between `new()` and `connect()`.
    psk_repo: RefCell<Option<JsPskRepository>>,
    /// Pending oneshot reply channels keyed by request_id.
    pending_replies: Rc<RefCell<HashMap<String, PendingReplyKind>>>,
    /// Monotonic counter for generating request IDs.
    next_request_id: Rc<Cell<u64>>,
    audit_callback: RefCell<Option<js_sys::Function>>,
}

#[wasm_bindgen]
impl UserClient {
    /// Create a new UserClient (sync — no proxy connection yet).
    ///
    /// This performs identity parsing in a synchronous context to avoid WASM
    /// stack issues with post-quantum crypto key derivation inside async futures.
    ///
    /// Call `connect()` afterwards to establish the proxy connection.
    ///
    /// - `connection_repository`: JS object implementing `Repository<ConnectionRecord>` for
    ///   auto-persistence
    /// - `initial_identity_data`: COSE-encoded identity keypair bytes (required)
    /// - `psk_repository`: Optional JS object implementing `Repository<PskRecord>` for reusable PSK
    ///   persistence
    #[wasm_bindgen(constructor)]
    pub fn new(
        connection_repository: JsConnectionRepository,
        initial_identity_data: Vec<u8>,
        psk_repository: Option<JsPskRepository>,
    ) -> Result<UserClient, JsValue> {
        tracing::info!(
            "[Agent Access WASM] new() called, identity_data={} bytes",
            initial_identity_data.len(),
        );

        if initial_identity_data.is_empty() {
            return Err(JsValue::from_str("Identity data is required"));
        }

        // Parse identity — done in sync context to avoid WASM async stack overflow
        // with ML-DSA-65 key derivation
        let identity = InMemoryIdentityProvider::from_bytes(&initial_identity_data)
            .map_err(|e| JsValue::from_str(&format!("Invalid identity data: {e}")))?;
        let identity_bytes = identity.to_bytes();
        tracing::info!(
            "[Agent Access WASM] identity provider created ({} bytes)",
            identity_bytes.len()
        );

        Ok(UserClient {
            client: RefCell::new(None),
            identity: identity_bytes,
            identity_provider: RefCell::new(Some(identity)),
            connection_repo: RefCell::new(Some(connection_repository)),
            psk_repo: RefCell::new(psk_repository),
            pending_replies: Rc::new(RefCell::new(HashMap::new())),
            next_request_id: Rc::new(Cell::new(0)),
            audit_callback: RefCell::new(None),
        })
    }

    /// Connect to the proxy server and start the event loop.
    ///
    /// Must be called after `new()`. Takes the proxy client and a JS callback
    /// for receiving notifications and requests. The event loop runs in the
    /// background; call `get_psk_token()` / `get_rendezvous_token()` to start
    /// accepting connections.
    pub async fn connect(
        &self,
        proxy_client: JsProxyClient,
        event_callback: js_sys::Function,
    ) -> Result<(), JsValue> {
        let identity = self.identity_provider.borrow_mut().take().ok_or_else(|| {
            JsValue::from_str("Identity already consumed (connect called twice?)")
        })?;

        let repo = self.connection_repo.borrow_mut().take().ok_or_else(|| {
            JsValue::from_str("Connection repository already consumed (connect called twice?)")
        })?;

        // Wrap JS repo in WasmRepositoryChannel → RepositoryConnectionStore
        let channel = WasmRepositoryChannel::new(repo);
        let repo_arc: Arc<dyn Repository<ConnectionRecord>> = Arc::new(channel);
        let connection_store = RepositoryConnectionStore::new(repo_arc);

        // Create proxy client wrapper
        let proxy = WasmProxyClient::new(proxy_client);
        tracing::info!("[Agent Access WASM] WasmProxyClient created, connecting to proxy...");

        // Build PSK store from optional JS repository
        let psk_store: Option<Box<dyn ap_client::PskStore>> =
            self.psk_repo.borrow_mut().take().map(|psk_repo| {
                let channel = WasmRepositoryChannel::new(psk_repo);
                let repo_arc: Arc<dyn Repository<PskRecord>> = Arc::new(channel);
                Box::new(RepositoryPskStore::new(repo_arc)) as Box<dyn ap_client::PskStore>
            });

        // Build audit log from callback
        let audit_log: Option<Box<dyn AuditLog>> = self
            .audit_callback
            .borrow()
            .clone()
            .map(|cb| Box::new(JsAuditLog { callback: cb }) as Box<dyn AuditLog>);

        // Connect — spawns the internal event loop and returns handle with channels
        let UserClientHandle {
            client,
            notifications: mut notification_rx,
            requests: mut request_rx,
        } = SdkUserClient::connect(
            Box::new(identity),
            Box::new(connection_store),
            Box::new(proxy),
            audit_log,
            psk_store,
        )
        .await
        .map_err(|e| {
            tracing::error!("[Agent Access WASM] UserClient::connect failed: {e}");
            JsValue::from_str(&e.to_string())
        })?;
        tracing::info!("[Agent Access WASM] connected to proxy successfully");

        *self.client.borrow_mut() = Some(client);

        // Spawn a single forwarder task that reads both channels and calls JS
        let pending_replies = self.pending_replies.clone();
        let next_request_id = self.next_request_id.clone();
        let callback = event_callback;

        wasm_bindgen_futures::spawn_local(async move {
            tracing::info!("Event forwarder task started");
            loop {
                tokio::select! {
                    notif = notification_rx.recv() => {
                        match notif {
                            Some(n) => {
                                tracing::info!("Forwarder: notification: {n:?}");
                                match notification_to_js(&n) {
                                    Ok(val) => { let _ = callback.call1(&JsValue::NULL, &val); }
                                    Err(e) => tracing::warn!("Forwarder: notification convert error: {e:?}"),
                                }
                            }
                            None => {
                                tracing::info!("Notification channel closed");
                                break;
                            }
                        }
                    }
                    req = request_rx.recv() => {
                        match req {
                            Some(r) => {
                                tracing::info!("Forwarder: request received");
                                let id = next_request_id.get();
                                next_request_id.set(id + 1);
                                let request_id = format!("req-{id}");

                                let (kind, js_val) = match r {
                                    UserClientRequest::VerifyFingerprint { fingerprint, identity, reply } => {
                                        let val = request_to_js(
                                            "verify_fingerprint_request",
                                            &serde_json::json!({
                                                "fingerprint": fingerprint,
                                                "identity": format!("{identity:?}"),
                                            }),
                                            &request_id,
                                        );
                                        (PendingReplyKind::Fingerprint(reply), val)
                                    }
                                    UserClientRequest::CredentialRequest { query, identity, reply } => {
                                        let val = request_to_js(
                                            "credential_request",
                                            &serde_json::json!({
                                                "query": serde_json::to_value(&query).unwrap_or_default(),
                                                "identity": format!("{identity:?}"),
                                            }),
                                            &request_id,
                                        );
                                        (PendingReplyKind::Credential(reply), val)
                                    }
                                };

                                pending_replies.borrow_mut().insert(request_id, kind);

                                match js_val {
                                    Ok(val) => { let _ = callback.call1(&JsValue::NULL, &val); }
                                    Err(e) => tracing::warn!("Forwarder: request convert error: {e:?}"),
                                }
                            }
                            None => {
                                tracing::info!("Request channel closed");
                                break;
                            }
                        }
                    }
                }
            }
            tracing::info!("Event forwarder task ended");
        });

        Ok(())
    }

    /// Get a clone of the connected SDK client, or error if not yet connected.
    fn get_client(&self) -> Result<SdkUserClient, JsValue> {
        self.client
            .borrow()
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Client not initialized"))
            .cloned()
    }

    /// Get a PSK token for pairing. Optionally provide a name for the connection.
    ///
    /// When `reusable` is true, the PSK is persisted in the configured PSK store
    /// and will not be consumed on first use. Requires a PSK repository to have
    /// been passed to the constructor.
    pub async fn get_psk_token(
        &self,
        name: Option<String>,
        reusable: bool,
    ) -> Result<String, JsValue> {
        self.get_client()?
            .get_psk_token(name, reusable)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Get a rendezvous token for pairing. Optionally provide a name for the connection.
    pub async fn get_rendezvous_token(&self, name: Option<String>) -> Result<String, JsValue> {
        let code = self
            .get_client()?
            .get_rendezvous_token(name)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(code.as_str().to_string())
    }

    /// Send a response to a pending request (fingerprint verification or credential request).
    pub fn send_response(&self, response: JsValue) -> Result<(), JsValue> {
        let parsed: serde_json::Value = tsify::serde_wasm_bindgen::from_value(response)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let resp_type = parsed["type"]
            .as_str()
            .ok_or_else(|| JsValue::from_str("missing type"))?;
        let request_id = parsed["request_id"]
            .as_str()
            .ok_or_else(|| JsValue::from_str("missing request_id"))?
            .to_string();

        let pending = self
            .pending_replies
            .borrow_mut()
            .remove(&request_id)
            .ok_or_else(|| {
                JsValue::from_str(&format!("No pending request with id: {request_id}"))
            })?;

        match (resp_type, pending) {
            ("verify_fingerprint", PendingReplyKind::Fingerprint(sender)) => {
                let approved = parsed["approved"]
                    .as_bool()
                    .ok_or_else(|| JsValue::from_str("missing approved"))?;
                let name = parsed["name"].as_str().map(|s| s.to_string());
                let _ = sender.send(FingerprintVerificationReply { approved, name });
            }
            ("respond_credential", PendingReplyKind::Credential(sender)) => {
                let approved = parsed["approved"]
                    .as_bool()
                    .ok_or_else(|| JsValue::from_str("missing approved"))?;
                let credential = if approved {
                    parsed.get("credential").and_then(|c| {
                        serde_json::from_value::<ap_client::CredentialData>(c.clone()).ok()
                    })
                } else {
                    None
                };
                let credential_id = parsed["credential_id"].as_str().map(|s| s.to_string());
                let _ = sender.send(CredentialRequestReply {
                    approved,
                    credential,
                    credential_id,
                });
            }
            _ => {
                return Err(JsValue::from_str(&format!(
                    "Response type '{resp_type}' does not match pending request"
                )));
            }
        }

        Ok(())
    }

    /// Get serialized identity data (COSE bytes) for proxy client construction.
    pub fn get_identity_data(&self) -> Vec<u8> {
        self.identity.clone()
    }

    /// Set a callback for audit log events.
    ///
    /// The callback receives a JS object for each security-relevant event
    /// (connection established, credential approved/denied, etc.).
    /// Call this before `connect()` so events are captured from the start.
    pub fn set_audit_callback(&self, callback: js_sys::Function) {
        *self.audit_callback.borrow_mut() = Some(callback);
    }

    /// Sign a proxy authentication challenge.
    ///
    /// Takes the challenge JSON from the proxy server and the COSE-encoded identity keypair.
    /// Returns the auth response JSON to send back to the proxy.
    ///
    /// This is used by the JavaScript `ProxyClient` implementation to complete
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

/// Serialize a `serde_json::Value` to a `JsValue` using wasm_bindgen serialization.
fn serialize_to_js(json: &serde_json::Value) -> Result<JsValue, JsValue> {
    let serializer = tsify::serde_wasm_bindgen::Serializer::new().serialize_maps_as_objects(true);
    serde::Serialize::serialize(json, &serializer).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Convert a `UserClientNotification` to a JS object.
fn notification_to_js(notif: &UserClientNotification) -> Result<JsValue, JsValue> {
    let json = match notif {
        UserClientNotification::Listening {} => {
            serde_json::json!({ "type": "listening" })
        }
        UserClientNotification::HandshakeStart {} => {
            serde_json::json!({ "type": "handshake_start" })
        }
        UserClientNotification::HandshakeProgress { message } => {
            serde_json::json!({ "type": "handshake_progress", "message": message })
        }
        UserClientNotification::HandshakeComplete {} => {
            serde_json::json!({ "type": "handshake_complete" })
        }
        UserClientNotification::HandshakeFingerprint {
            fingerprint,
            identity,
        } => {
            serde_json::json!({ "type": "handshake_fingerprint", "fingerprint": fingerprint, "identity": format!("{identity:?}") })
        }
        UserClientNotification::FingerprintVerified {} => {
            serde_json::json!({ "type": "fingerprint_verified" })
        }
        UserClientNotification::FingerprintRejected { reason } => {
            serde_json::json!({ "type": "fingerprint_rejected", "reason": reason })
        }
        UserClientNotification::CredentialApproved {
            domain,
            credential_id,
        } => {
            serde_json::json!({ "type": "credential_approved", "domain": domain, "credential_id": credential_id })
        }
        UserClientNotification::CredentialDenied {
            domain,
            credential_id,
        } => {
            serde_json::json!({ "type": "credential_denied", "domain": domain, "credential_id": credential_id })
        }
        UserClientNotification::SessionRefreshed { fingerprint } => {
            serde_json::json!({ "type": "session_refreshed", "fingerprint": format!("{fingerprint:?}") })
        }
        UserClientNotification::ClientDisconnected {} => {
            serde_json::json!({ "type": "client_disconnected" })
        }
        UserClientNotification::Reconnecting { attempt } => {
            serde_json::json!({ "type": "reconnecting", "attempt": attempt })
        }
        UserClientNotification::Reconnected {} => {
            serde_json::json!({ "type": "reconnected" })
        }
        UserClientNotification::Error { message, context } => {
            serde_json::json!({ "type": "error", "message": message, "context": context })
        }
    };

    serialize_to_js(&json)
}

/// Convert a `UserClientRequest` into a JS event object with a request_id.
fn request_to_js(
    event_type: &str,
    fields: &serde_json::Value,
    request_id: &str,
) -> Result<JsValue, JsValue> {
    let mut json = fields.clone();
    if let Some(obj) = json.as_object_mut() {
        obj.insert("type".to_string(), serde_json::json!(event_type));
        obj.insert("request_id".to_string(), serde_json::json!(request_id));
    }

    serialize_to_js(&json)
}

/// Convert an `AuditEvent` to a JS object for the audit callback.
fn audit_event_to_js(event: &AuditEvent<'_>) -> Result<JsValue, JsValue> {
    let json = match event {
        AuditEvent::ConnectionEstablished {
            remote_identity,
            remote_name,
            connection_type,
        } => {
            serde_json::json!({
                "type": "connection_established",
                "remoteIdentity": format!("{remote_identity:?}"),
                "remoteName": remote_name,
                "connectionType": match connection_type {
                    AuditConnectionType::Rendezvous => "rendezvous",
                    AuditConnectionType::Psk => "psk",
                },
            })
        }
        AuditEvent::SessionRefreshed { remote_identity } => {
            serde_json::json!({
                "type": "session_refreshed",
                "remoteIdentity": format!("{remote_identity:?}"),
            })
        }
        AuditEvent::ConnectionRejected { remote_identity } => {
            serde_json::json!({
                "type": "connection_rejected",
                "remoteIdentity": format!("{remote_identity:?}"),
            })
        }
        AuditEvent::CredentialRequested {
            query,
            remote_identity,
            request_id,
        } => {
            serde_json::json!({
                "type": "credential_requested",
                "remoteIdentity": format!("{remote_identity:?}"),
                "requestId": request_id,
                "query": serde_json::to_value(query).unwrap_or_default(),
            })
        }
        AuditEvent::CredentialApproved {
            query,
            domain,
            remote_identity,
            request_id,
            credential_id,
            fields,
        } => {
            let mut field_names = Vec::new();
            if fields.has_username {
                field_names.push("username");
            }
            if fields.has_password {
                field_names.push("password");
            }
            if fields.has_totp {
                field_names.push("totp");
            }
            if fields.has_uri {
                field_names.push("uri");
            }
            if fields.has_notes {
                field_names.push("notes");
            }
            serde_json::json!({
                "type": "credential_approved",
                "remoteIdentity": format!("{remote_identity:?}"),
                "requestId": request_id,
                "query": serde_json::to_value(query).unwrap_or_default(),
                "domain": domain,
                "credentialId": credential_id,
                "fields": field_names,
            })
        }
        AuditEvent::CredentialDenied {
            query,
            domain,
            remote_identity,
            request_id,
            credential_id,
        } => {
            serde_json::json!({
                "type": "credential_denied",
                "remoteIdentity": format!("{remote_identity:?}"),
                "requestId": request_id,
                "query": serde_json::to_value(query).unwrap_or_default(),
                "domain": domain,
                "credentialId": credential_id,
            })
        }
        _ => {
            // Non-exhaustive catch-all for future variants
            return Err(JsValue::from_str("Unknown audit event variant"));
        }
    };

    serialize_to_js(&json)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- sign_proxy_challenge (underlying logic) ---

    #[test]
    fn sign_challenge_roundtrip() {
        use ap_proxy_protocol::Challenge;

        let keypair = IdentityKeyPair::generate();
        let challenge = Challenge::new();

        // Sign it
        let response = challenge.sign(&keypair);

        // Verify the signature
        let identity = keypair.identity();
        assert!(response.verify(&challenge, &identity));
    }

    #[test]
    fn sign_challenge_wrong_identity_fails() {
        use ap_proxy_protocol::Challenge;

        let keypair1 = IdentityKeyPair::generate();
        let keypair2 = IdentityKeyPair::generate();
        let challenge = Challenge::new();

        let response = challenge.sign(&keypair1);
        assert!(!response.verify(&challenge, &keypair2.identity()));
    }

    #[test]
    fn messages_auth_challenge_json_roundtrip() {
        use ap_proxy_protocol::Challenge;

        let challenge = Challenge::new();
        let msg = Messages::AuthChallenge(challenge);
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: Messages = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, Messages::AuthChallenge(_)));
    }

    #[test]
    fn identity_keypair_cose_roundtrip() {
        let keypair = IdentityKeyPair::generate();
        let cose = keypair.to_cose();
        let restored = IdentityKeyPair::from_cose(&cose).unwrap();

        // Verify by signing with restored key and verifying with original identity
        use ap_proxy_protocol::Challenge;
        let challenge = Challenge::new();
        let response = challenge.sign(&restored);
        assert!(response.verify(&challenge, &keypair.identity()));
    }
}
