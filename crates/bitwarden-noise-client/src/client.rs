//! Remote Client Core - Pure library implementation
//!
//! Connects through a proxy to a user-client using PSK + Noise protocols.
//! Uses async channels for event-driven communication with UI layer.

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use bitwarden_noise::{NoiseProtocol, psk::derive_psk_from_pairing_code};
use futures_util::{SinkExt, StreamExt};
use tokio::{
    sync::{Mutex, mpsc},
    time::timeout,
};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{debug, info, warn};

use crate::{
    error::RemoteClientError,
    keypair_storage::get_or_create_static_keypair,
    session_cache::SessionCache,
    types::{
        CredentialData, CredentialRequestPayload, CredentialResponsePayload, ProtocolMessage,
        RemoteClientConfig, RemoteClientEvent,
    },
};

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type WsSink = futures_util::stream::SplitSink<WsStream, Message>;
type WsSource = futures_util::stream::SplitStream<WsStream>;

/// Default timeout for operations
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Remote client for connecting to a user-client through a proxy
pub struct RemoteClient {
    session_cache: SessionCache,
    config: Option<RemoteClientConfig>,
    noise_protocol: Option<NoiseProtocol>,
    psk: Option<Vec<u8>>,
    ws_sink: Option<Arc<Mutex<WsSink>>>,
    ws_source: Option<Arc<Mutex<WsSource>>>,
    username: Option<String>,
}

impl Default for RemoteClient {
    fn default() -> Self {
        Self::new(None)
    }
}

impl RemoteClient {
    /// Create a new remote client
    ///
    /// # Arguments
    /// * `session_cache` - Optional custom session cache
    pub fn new(session_cache: Option<SessionCache>) -> Self {
        Self {
            session_cache: session_cache.unwrap_or_default(),
            config: None,
            noise_protocol: None,
            psk: None,
            ws_sink: None,
            ws_source: None,
            username: None,
        }
    }

    /// Connect to the proxy and establish a secure channel
    ///
    /// # Arguments
    /// * `config` - Connection configuration
    /// * `event_tx` - Channel to send events to the UI
    pub async fn connect(
        &mut self,
        config: RemoteClientConfig,
        event_tx: mpsc::Sender<RemoteClientEvent>,
    ) -> Result<(), RemoteClientError> {
        self.config = Some(config.clone());

        // Step 1: Connect to proxy
        event_tx
            .send(RemoteClientEvent::Connecting {
                proxy_url: config.proxy_url.clone(),
            })
            .await
            .ok();
        info!("Connecting to proxy: {}", config.proxy_url);

        let (ws_stream, _) = connect_async(&config.proxy_url)
            .await
            .map_err(|e| RemoteClientError::ConnectionFailed(e.to_string()))?;

        let (sink, source) = ws_stream.split();
        self.ws_sink = Some(Arc::new(Mutex::new(sink)));
        self.ws_source = Some(Arc::new(Mutex::new(source)));

        // Send auth message to proxy
        let session_id = format!("session-{}", now_millis());
        let auth_msg = ProtocolMessage::Auth {
            client_id: config.client_id.clone(),
            username: config.username.clone(),
            session_id,
        };
        self.send_message(&auth_msg).await?;

        // Wait for auth response
        let auth_response = self.receive_message().await?;
        match auth_response {
            ProtocolMessage::AuthResponse { success, error } => {
                if !success {
                    let err_msg = error.unwrap_or_else(|| "Unknown error".to_string());
                    return Err(RemoteClientError::ProxyAuthFailed(err_msg));
                }
            }
            _ => {
                return Err(RemoteClientError::ProxyAuthFailed(
                    "Unexpected response".to_string(),
                ));
            }
        }

        let client_id = config
            .client_id
            .clone()
            .unwrap_or_else(|| "anonymous".to_string());
        event_tx
            .send(RemoteClientEvent::Connected {
                client_id: client_id.clone(),
            })
            .await
            .ok();
        info!("Connected to proxy as: {}", client_id);

        // Step 2: Load or create static keypair for this device
        let device_id = format!(
            "remote-client-{}-{}",
            config.username,
            config.client_id.as_deref().unwrap_or("default")
        );
        let static_keypair = get_or_create_static_keypair(&device_id)?;
        debug!("Static keypair loaded/created for device: {}", device_id);

        // Step 3: Check for cached PSK
        let cached_psk = if config.use_cached_auth {
            self.session_cache
                .load(&config.username, config.client_id.as_deref())
        } else {
            None
        };

        event_tx
            .send(RemoteClientEvent::CacheCheck {
                has_cached_auth: cached_psk.is_some(),
                username: config.username.clone(),
                client_id: config.client_id.clone(),
            })
            .await
            .ok();

        if let Some(psk) = cached_psk {
            info!("Using cached PSK");
            self.psk = Some(psk);

            // Notify user-client we're using cached auth
            let cached_auth_msg = ProtocolMessage::CachedAuth {
                username: config.username.clone(),
                client_id: config.client_id.clone(),
            };
            self.send_message(&cached_auth_msg).await?;

            event_tx
                .send(RemoteClientEvent::AuthComplete {
                    phase: "KE3".to_string(),
                    session_cached: true,
                })
                .await
                .ok();
        } else {
            // Step 4: Derive PSK from pairing code
            event_tx
                .send(RemoteClientEvent::AuthStart {
                    phase: "KE1".to_string(),
                })
                .await
                .ok();
            info!("Starting PSK authentication");

            let (psk, username) = derive_psk_from_pairing_code(&config.pairing_code)
                .map_err(|e| RemoteClientError::InvalidPairingCode(e.to_string()))?;

            self.psk = Some(psk.to_vec());
            self.username = Some(username);
            info!("PSK derived from pairing code");

            // Cache PSK if enabled
            if config.use_cached_auth {
                self.session_cache
                    .save(&config.username, &psk, config.client_id.as_deref())?;
                info!("PSK cached for future connections");
            }

            // Notify user-client this is first-time auth
            let first_time_msg = ProtocolMessage::FirstTimeAuth {
                username: config.username.clone(),
                client_id: config.client_id.clone(),
            };
            self.send_message(&first_time_msg).await?;

            event_tx
                .send(RemoteClientEvent::AuthComplete {
                    phase: "KE3".to_string(),
                    session_cached: config.use_cached_auth,
                })
                .await
                .ok();
            info!("PSK authentication complete");
        }

        // Step 5: Perform Noise handshake
        event_tx.send(RemoteClientEvent::HandshakeStart).await.ok();
        info!("Starting Noise handshake");

        let psk = self
            .psk
            .as_ref()
            .ok_or(RemoteClientError::NotInitialized)?
            .clone();

        // Initialize Noise Protocol (initiator) with static keys and PSK
        let mut noise = NoiseProtocol::new(true, Some(static_keypair.secret_key()), Some(psk))
            .map_err(|e| RemoteClientError::NoiseProtocol(e.to_string()))?;

        // Send message 1
        let message1 = noise
            .write_message(None)
            .map_err(|e| RemoteClientError::HandshakeFailed(e.to_string()))?;

        let msg1 = ProtocolMessage::NoiseMessage1 {
            data: STANDARD.encode(&message1),
        };
        self.send_message(&msg1).await?;

        event_tx
            .send(RemoteClientEvent::HandshakeProgress {
                message: "Sent message 1".to_string(),
            })
            .await
            .ok();
        debug!("Sent Noise message 1");

        // Wait for message 2
        let msg2_response = timeout(DEFAULT_TIMEOUT, self.receive_message())
            .await
            .map_err(|_| RemoteClientError::Timeout("Waiting for Noise message 2".to_string()))??;

        let message2_data = match msg2_response {
            ProtocolMessage::NoiseMessage2 { data } => STANDARD.decode(&data).map_err(|e| {
                RemoteClientError::HandshakeFailed(format!("Invalid base64: {}", e))
            })?,
            _ => {
                return Err(RemoteClientError::HandshakeFailed(
                    "Expected NoiseMessage2".to_string(),
                ));
            }
        };

        // Process message 2
        noise
            .read_message(&message2_data)
            .map_err(|e| RemoteClientError::HandshakeFailed(e.to_string()))?;

        event_tx
            .send(RemoteClientEvent::HandshakeProgress {
                message: "Received message 2".to_string(),
            })
            .await
            .ok();
        debug!("Received Noise message 2");

        // Send message 3
        let message3 = noise
            .write_message(None)
            .map_err(|e| RemoteClientError::HandshakeFailed(e.to_string()))?;

        let msg3 = ProtocolMessage::NoiseMessage3 {
            data: STANDARD.encode(&message3),
        };
        self.send_message(&msg3).await?;

        // Split to get transport keys
        noise
            .split()
            .map_err(|e| RemoteClientError::HandshakeFailed(e.to_string()))?;

        self.noise_protocol = Some(noise);

        event_tx
            .send(RemoteClientEvent::HandshakeComplete)
            .await
            .ok();
        info!("Noise handshake complete");

        // Step 6: Ready for credential requests
        event_tx
            .send(RemoteClientEvent::Ready {
                can_request_credentials: true,
            })
            .await
            .ok();
        info!("Connection fully established and ready");

        Ok(())
    }

    /// Request a credential over the secure channel
    ///
    /// # Arguments
    /// * `domain` - The domain/service to request credential for
    pub async fn request_credential(
        &mut self,
        domain: &str,
    ) -> Result<CredentialData, RemoteClientError> {
        let noise = self
            .noise_protocol
            .as_mut()
            .ok_or(RemoteClientError::SecureChannelNotEstablished)?;

        if !noise.is_handshake_complete() {
            return Err(RemoteClientError::SecureChannelNotEstablished);
        }

        let config = self
            .config
            .as_ref()
            .ok_or(RemoteClientError::NotInitialized)?;

        // Sliced string is a UUID and isn't going to contain wide chars
        #[allow(clippy::string_slice)]
        let request_id = format!("req-{}-{}", now_millis(), &uuid_v4()[..8]);

        info!("Requesting credential for domain: {}", domain);

        // Create and encrypt request
        let request = CredentialRequestPayload {
            request_type: "credential_request".to_string(),
            username: config.username.clone(),
            domain: domain.to_string(),
            timestamp: now_millis(),
            request_id: request_id.clone(),
        };

        let request_json = serde_json::to_string(&request)?;
        let encrypted = noise
            .encrypt_message(request_json.as_bytes())
            .map_err(|e| RemoteClientError::NoiseProtocol(e.to_string()))?;

        let msg = ProtocolMessage::CredentialRequest {
            encrypted: STANDARD.encode(&encrypted),
        };
        self.send_message(&msg).await?;

        // Wait for response
        let response = timeout(
            DEFAULT_TIMEOUT,
            self.wait_for_credential_response(&request_id),
        )
        .await
        .map_err(|_| {
            RemoteClientError::Timeout(format!("Credential request for domain: {}", domain))
        })??;

        Ok(response)
    }

    /// Check if the secure channel is established
    pub fn is_ready(&self) -> bool {
        self.noise_protocol
            .as_ref()
            .is_some_and(|n| n.is_handshake_complete())
    }

    /// Close the connection
    pub async fn close(&mut self) {
        if let Some(sink) = self.ws_sink.take() {
            if let Ok(mut sink) = sink.try_lock() {
                sink.close().await.ok();
            }
        }
        self.ws_source = None;
        self.noise_protocol = None;
        info!("Connection closed");
    }

    /// Get the session cache for management operations
    pub fn session_cache(&self) -> &SessionCache {
        &self.session_cache
    }

    async fn send_message(&self, msg: &ProtocolMessage) -> Result<(), RemoteClientError> {
        let sink = self
            .ws_sink
            .as_ref()
            .ok_or(RemoteClientError::NotInitialized)?;

        let json = serde_json::to_string(msg)?;
        let mut sink = sink.lock().await;
        sink.send(Message::Text(json))
            .await
            .map_err(|e| RemoteClientError::WebSocket(e.to_string()))?;

        Ok(())
    }

    async fn receive_message(&self) -> Result<ProtocolMessage, RemoteClientError> {
        let source = self
            .ws_source
            .as_ref()
            .ok_or(RemoteClientError::NotInitialized)?;

        let mut source = source.lock().await;
        loop {
            debug!("Waiting for WebSocket message...");
            match source.next().await {
                Some(Ok(Message::Text(text))) => {
                    debug!("Received WebSocket text message: {}", text);
                    match serde_json::from_str::<ProtocolMessage>(&text) {
                        Ok(msg) => {
                            debug!("Parsed protocol message: {:?}", msg);
                            return Ok(msg);
                        }
                        Err(e) => {
                            // Log but don't fail - might be a message type we don't handle
                            warn!(
                                "Failed to parse message as ProtocolMessage: {} - raw: {}",
                                e, text
                            );
                            continue;
                        }
                    }
                }
                Some(Ok(Message::Binary(data))) => {
                    // Binary messages may contain JSON - try to parse as text
                    debug!(
                        "Received binary message ({} bytes), attempting to parse as JSON",
                        data.len()
                    );
                    match String::from_utf8(data) {
                        Ok(text) => {
                            debug!("Binary message as text: {}", text);
                            match serde_json::from_str::<ProtocolMessage>(&text) {
                                Ok(msg) => {
                                    debug!("Parsed binary message as protocol message: {:?}", msg);
                                    return Ok(msg);
                                }
                                Err(e) => {
                                    warn!(
                                        "Failed to parse binary message as ProtocolMessage: {} - raw: {}",
                                        e, text
                                    );
                                    continue;
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Binary message is not valid UTF-8: {}", e);
                            continue;
                        }
                    }
                }
                Some(Ok(Message::Ping(data))) => {
                    debug!("Received ping ({} bytes)", data.len());
                    continue;
                }
                Some(Ok(Message::Pong(data))) => {
                    debug!("Received pong ({} bytes)", data.len());
                    continue;
                }
                Some(Ok(Message::Close(frame))) => {
                    debug!("Received close frame: {:?}", frame);
                    return Err(RemoteClientError::ChannelClosed);
                }
                Some(Ok(Message::Frame(_))) => {
                    debug!("Received raw frame, ignoring");
                    continue;
                }
                Some(Err(e)) => {
                    debug!("WebSocket error: {}", e);
                    return Err(RemoteClientError::WebSocket(e.to_string()));
                }
                None => {
                    debug!("WebSocket stream ended");
                    return Err(RemoteClientError::ChannelClosed);
                }
            }
        }
    }

    async fn wait_for_credential_response(
        &mut self,
        request_id: &str,
    ) -> Result<CredentialData, RemoteClientError> {
        loop {
            let msg = self.receive_message().await?;

            if let ProtocolMessage::CredentialResponse { encrypted } = msg {
                let encrypted_bytes = STANDARD.decode(&encrypted).map_err(|e| {
                    RemoteClientError::Serialization(format!("Invalid base64: {}", e))
                })?;

                let noise = self
                    .noise_protocol
                    .as_mut()
                    .ok_or(RemoteClientError::SecureChannelNotEstablished)?;

                let decrypted = noise
                    .decrypt_message(&encrypted_bytes)
                    .map_err(|e| RemoteClientError::NoiseProtocol(e.to_string()))?;

                let response: CredentialResponsePayload = serde_json::from_slice(&decrypted)?;

                // Check if this response matches our request ID
                if let Some(ref resp_id) = response.request_id {
                    if resp_id != request_id {
                        warn!("Received response for different request, ignoring");
                        continue;
                    }
                }

                if let Some(error) = response.error {
                    return Err(RemoteClientError::CredentialRequestFailed(error));
                }

                return response.credential.ok_or_else(|| {
                    RemoteClientError::CredentialRequestFailed(
                        "No credential in response".to_string(),
                    )
                });
            }
            // Ignore other message types while waiting
        }
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn uuid_v4() -> String {
    // Simple UUID v4 generation without external dependency
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).unwrap_or_default();

    // Set version (4) and variant bits
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}
