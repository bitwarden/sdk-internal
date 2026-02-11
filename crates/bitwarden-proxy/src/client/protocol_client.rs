use crate::{
    auth::{IdentityFingerprint, IdentityKeyPair},
    error::ProxyError,
    messages::Messages,
};
use futures::stream::StreamExt;
use futures::SinkExt;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio_tungstenite::{WebSocketStream, connect_async, tungstenite::Message};

use super::config::{ClientState, IncomingMessage, ProxyClientConfig};

type WsStream = WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type WsSink = futures::stream::SplitSink<WsStream, Message>;
type WsSource = futures::stream::SplitStream<WsStream>;

/// Client for connecting to and communicating through a bitwarden-proxy server.
///
/// This is the main client API for connecting to a proxy server, authenticating,
/// discovering peers via rendezvous codes, and sending messages.
///
/// # Lifecycle
///
/// 1. Create client with [`new()`](ProxyProtocolClient::new)
/// 2. Connect and authenticate with [`connect()`](ProxyProtocolClient::connect)
/// 3. Perform operations (send messages, request rendezvous codes, etc.)
/// 4. Disconnect with [`disconnect()`](ProxyProtocolClient::disconnect)
///
/// # Examples
///
/// Basic usage:
///
/// ```no_run
/// use bitwarden_proxy::{ProxyClientConfig, ProxyProtocolClient, IncomingMessage};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create and connect
/// let config = ProxyClientConfig {
///     proxy_url: "ws://localhost:8080".to_string(),
///     identity_keypair: None,
/// };
/// let mut client = ProxyProtocolClient::new(config);
/// let mut incoming = client.connect().await?;
///
/// // Handle messages
/// tokio::spawn(async move {
///     while let Some(msg) = incoming.recv().await {
///         match msg {
///             IncomingMessage::Send { source, payload, .. } => {
///                 println!("Got message from {:?}", source);
///             }
///             _ => {}
///         }
///     }
/// });
///
/// // Send a message
/// // client.send_to(target_fingerprint, b"Hello".to_vec()).await?;
/// # Ok(())
/// # }
/// ```
pub struct ProxyProtocolClient {
    // Configuration
    config: ProxyClientConfig,
    identity: Arc<IdentityKeyPair>,

    // Connection state
    state: Arc<Mutex<ClientState>>,

    // WebSocket components (None when disconnected)
    outgoing_tx: Option<mpsc::UnboundedSender<Message>>,

    // Task handles for cleanup
    read_task_handle: Option<JoinHandle<()>>,
    write_task_handle: Option<JoinHandle<()>>,
}

impl ProxyProtocolClient {
    /// Create a new proxy client with the given configuration.
    ///
    /// This does not establish a connection - call [`connect()`](ProxyProtocolClient::connect)
    /// to connect and authenticate.
    ///
    /// If `config.identity_keypair` is `None`, a new random identity will be generated.
    /// Otherwise, the provided identity will be used for authentication.
    ///
    /// # Examples
    ///
    /// Create client with new identity:
    ///
    /// ```
    /// use bitwarden_proxy::{ProxyClientConfig, ProxyProtocolClient};
    ///
    /// let config = ProxyClientConfig {
    ///     proxy_url: "ws://localhost:8080".to_string(),
    ///     identity_keypair: None, // Will generate new identity
    /// };
    /// let client = ProxyProtocolClient::new(config);
    /// println!("Client fingerprint: {:?}", client.fingerprint());
    /// ```
    ///
    /// Create client with existing identity:
    ///
    /// ```
    /// use bitwarden_proxy::{ProxyClientConfig, ProxyProtocolClient, IdentityKeyPair};
    ///
    /// let keypair = IdentityKeyPair::generate();
    /// let config = ProxyClientConfig {
    ///     proxy_url: "ws://localhost:8080".to_string(),
    ///     identity_keypair: Some(keypair),
    /// };
    /// let client = ProxyProtocolClient::new(config);
    /// ```
    pub fn new(mut config: ProxyClientConfig) -> Self {
        let identity = Arc::new(
            config
                .identity_keypair
                .take()
                .unwrap_or_else(IdentityKeyPair::generate),
        );

        Self {
            config,
            identity,
            state: Arc::new(Mutex::new(ClientState::Disconnected)),
            outgoing_tx: None,
            read_task_handle: None,
            write_task_handle: None,
        }
    }

    /// Connect to the proxy server and perform authentication.
    ///
    /// Establishes a WebSocket connection, completes the challenge-response authentication,
    /// and returns a channel for receiving incoming messages.
    ///
    /// # Authentication Flow
    ///
    /// 1. Connect to WebSocket at the configured URL
    /// 2. Receive authentication challenge from server
    /// 3. Sign challenge with client's private key
    /// 4. Send signed response to server
    /// 5. Server verifies signature and accepts connection
    ///
    /// # Timeout
    ///
    /// Authentication must complete within 5 seconds or this method returns
    /// [`ProxyError::AuthenticationTimeout`].
    ///
    /// # Errors
    ///
    /// - [`ProxyError::AlreadyConnected`] if already connected
    /// - [`ProxyError::WebSocket`] if connection fails
    /// - [`ProxyError::AuthenticationFailed`] if signature verification fails
    /// - [`ProxyError::AuthenticationTimeout`] if authentication takes too long
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use bitwarden_proxy::{ProxyClientConfig, ProxyProtocolClient, IncomingMessage};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = ProxyClientConfig {
    ///     proxy_url: "ws://localhost:8080".to_string(),
    ///     identity_keypair: None,
    /// };
    /// let mut client = ProxyProtocolClient::new(config);
    ///
    /// // Connect and get incoming message channel
    /// let mut incoming = client.connect().await?;
    ///
    /// // Handle messages
    /// while let Some(msg) = incoming.recv().await {
    ///     println!("Received: {:?}", msg);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect(
        &mut self,
    ) -> Result<mpsc::UnboundedReceiver<IncomingMessage>, ProxyError> {
        // Check not already connected
        {
            let state = self.state.lock().await;
            if !matches!(*state, ClientState::Disconnected) {
                return Err(ProxyError::AlreadyConnected);
            }
        }

        // Connect WebSocket
        let (ws_stream, _) = connect_async(&self.config.proxy_url).await?;

        // Split into read/write
        let (ws_sink, ws_source) = ws_stream.split();

        // Update state to Connected
        *self.state.lock().await = ClientState::Connected;

        // Create channels
        let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel::<Message>();
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel::<IncomingMessage>();
        let (auth_tx, mut auth_rx) = mpsc::unbounded_channel::<Result<(), ProxyError>>();

        // Spawn write task
        let write_handle = tokio::spawn(Self::write_task(ws_sink, outgoing_rx));

        // Spawn read task (handles auth + message routing)
        let read_handle = tokio::spawn(Self::read_task(
            ws_source,
            outgoing_tx.clone(),
            incoming_tx,
            Arc::clone(&self.identity),
            self.state.clone(),
            auth_tx,
        ));

        // Wait for authentication to complete
        match tokio::time::timeout(tokio::time::Duration::from_secs(5), auth_rx.recv()).await {
            Ok(Some(Ok(()))) => {
                // Authentication succeeded
            }
            Ok(Some(Err(e))) => {
                // Authentication failed
                self.read_task_handle = Some(read_handle);
                self.write_task_handle = Some(write_handle);
                self.disconnect().await?;
                return Err(e);
            }
            Ok(None) | Err(_) => {
                // Channel closed or timeout
                self.read_task_handle = Some(read_handle);
                self.write_task_handle = Some(write_handle);
                self.disconnect().await?;
                return Err(ProxyError::AuthenticationTimeout);
            }
        }

        // Store handles and tx
        self.outgoing_tx = Some(outgoing_tx);
        self.read_task_handle = Some(read_handle);
        self.write_task_handle = Some(write_handle);

        Ok(incoming_rx)
    }

    /// Send a message to another authenticated client.
    pub async fn send_to(
        &self,
        destination: IdentityFingerprint,
        payload: Vec<u8>,
    ) -> Result<(), ProxyError> {
        // Check authenticated
        {
            let state = self.state.lock().await;
            if !matches!(*state, ClientState::Authenticated { .. }) {
                return Err(ProxyError::NotConnected);
            }
        }

        // Create Send message without source (server will add it)
        let msg = Messages::Send {
            source: None,
            destination,
            payload,
        };

        let json = serde_json::to_string(&msg)?;

        // Send via outgoing_tx channel
        if let Some(tx) = &self.outgoing_tx {
            tx.send(Message::Text(json))
                .map_err(|_| ProxyError::ChannelSendFailed)?;
            Ok(())
        } else {
            Err(ProxyError::NotConnected)
        }
    }

    /// Request a rendezvous code from the server.
    pub async fn request_rendezvous(&self) -> Result<(), ProxyError> {
        // Check authenticated
        {
            let state = self.state.lock().await;
            if !matches!(*state, ClientState::Authenticated { .. }) {
                return Err(ProxyError::NotConnected);
            }
        }

        // Send GetRendevouz message
        let msg = Messages::GetRendevouz;
        let json = serde_json::to_string(&msg)?;

        // Send via outgoing_tx channel
        if let Some(tx) = &self.outgoing_tx {
            tx.send(Message::Text(json))
                .map_err(|_| ProxyError::ChannelSendFailed)?;
            Ok(())
        } else {
            Err(ProxyError::NotConnected)
        }
    }

    /// Look up a peer's identity using a rendezvous code.
    pub async fn request_identity(
        &self,
        rendezvous_code: crate::rendevouz::RendevouzCode,
    ) -> Result<(), ProxyError> {
        // Check authenticated
        {
            let state = self.state.lock().await;
            if !matches!(*state, ClientState::Authenticated { .. }) {
                return Err(ProxyError::NotConnected);
            }
        }

        // Send GetIdentity message
        let msg = Messages::GetIdentity(rendezvous_code);
        let json = serde_json::to_string(&msg)?;

        // Send via outgoing_tx channel
        if let Some(tx) = &self.outgoing_tx {
            tx.send(Message::Text(json))
                .map_err(|_| ProxyError::ChannelSendFailed)?;
            Ok(())
        } else {
            Err(ProxyError::NotConnected)
        }
    }

    /// Get this client's identity fingerprint.
    pub fn fingerprint(&self) -> IdentityFingerprint {
        self.identity.identity().fingerprint()
    }

    /// Check if the client is currently authenticated.
    pub async fn is_authenticated(&self) -> bool {
        matches!(*self.state.lock().await, ClientState::Authenticated { .. })
    }

    /// Disconnect from the proxy server and clean up resources.
    pub async fn disconnect(&mut self) -> Result<(), ProxyError> {
        // Abort tasks
        if let Some(handle) = self.read_task_handle.take() {
            handle.abort();
        }
        if let Some(handle) = self.write_task_handle.take() {
            handle.abort();
        }

        // Clear state
        *self.state.lock().await = ClientState::Disconnected;

        // Close channels
        self.outgoing_tx = None;

        Ok(())
    }

    /// Write task: sends messages from channel to WebSocket
    async fn write_task(mut ws_sink: WsSink, mut outgoing_rx: mpsc::UnboundedReceiver<Message>) {
        while let Some(msg) = outgoing_rx.recv().await {
            if ws_sink.send(msg).await.is_err() {
                break;
            }
        }
    }

    /// Read task: handles authentication and routes messages
    async fn read_task(
        mut ws_source: WsSource,
        outgoing_tx: mpsc::UnboundedSender<Message>,
        incoming_tx: mpsc::UnboundedSender<IncomingMessage>,
        identity: Arc<IdentityKeyPair>,
        state: Arc<Mutex<ClientState>>,
        auth_tx: mpsc::UnboundedSender<Result<(), ProxyError>>,
    ) {
        // Handle authentication
        match Self::handle_authentication(&mut ws_source, &outgoing_tx, &identity).await {
            Ok(fingerprint) => {
                *state.lock().await = ClientState::Authenticated { fingerprint };
                // Notify that authentication succeeded
                let _ = auth_tx.send(Ok(()));
            }
            Err(e) => {
                tracing::error!("Authentication failed: {}", e);
                *state.lock().await = ClientState::Disconnected;
                // Notify that authentication failed
                let _ = auth_tx.send(Err(e));
                return;
            }
        }

        // Enter message loop
        if let Err(e) = Self::message_loop(ws_source, incoming_tx).await {
            tracing::error!("Message loop error: {}", e);
        }

        *state.lock().await = ClientState::Disconnected;
    }

    /// Handle authentication challenge-response
    async fn handle_authentication(
        ws_source: &mut WsSource,
        outgoing_tx: &mpsc::UnboundedSender<Message>,
        identity: &Arc<IdentityKeyPair>,
    ) -> Result<IdentityFingerprint, ProxyError> {
        // Receive AuthChallenge
        let challenge_msg = ws_source
            .next()
            .await
            .ok_or(ProxyError::ConnectionClosed)?
            .map_err(|e| ProxyError::WebSocket(e.to_string()))?;

        let challenge = match challenge_msg {
            Message::Text(text) => match serde_json::from_str::<Messages>(&text)? {
                Messages::AuthChallenge(c) => c,
                _ => return Err(ProxyError::InvalidMessage("Expected AuthChallenge".into())),
            },
            _ => return Err(ProxyError::InvalidMessage("Expected text message".into())),
        };

        // Sign challenge
        let response = challenge.sign(identity);
        let auth_response = Messages::AuthResponse(identity.identity(), response);
        let auth_json = serde_json::to_string(&auth_response)?;

        // Send auth response
        outgoing_tx
            .send(Message::Text(auth_json))
            .map_err(|_| ProxyError::ChannelSendFailed)?;

        // Authentication complete - server doesn't send confirmation
        Ok(identity.identity().fingerprint())
    }

    /// Message loop: routes incoming messages to channel
    async fn message_loop(
        mut ws_source: WsSource,
        incoming_tx: mpsc::UnboundedSender<IncomingMessage>,
    ) -> Result<(), ProxyError> {
        while let Some(msg_result) = ws_source.next().await {
            let msg = msg_result.map_err(|e| ProxyError::WebSocket(e.to_string()))?;

            match msg {
                Message::Text(text) => {
                    let parsed: Messages = serde_json::from_str(&text)?;
                    match parsed {
                        Messages::Send {
                            source,
                            destination,
                            payload,
                        } => {
                            // Server always includes source when forwarding messages
                            if let Some(source) = source {
                                incoming_tx
                                    .send(IncomingMessage::Send {
                                        source,
                                        destination,
                                        payload,
                                    })
                                    .ok();
                            } else {
                                tracing::warn!("Received Send message without source");
                            }
                        }
                        Messages::RendevouzInfo(code) => {
                            incoming_tx.send(IncomingMessage::RendevouzInfo(code)).ok();
                        }
                        Messages::IdentityInfo {
                            fingerprint,
                            identity,
                        } => {
                            incoming_tx
                                .send(IncomingMessage::IdentityInfo {
                                    fingerprint,
                                    identity,
                                })
                                .ok();
                        }
                        Messages::GetIdentity(_) => {
                            tracing::warn!("Received GetIdentity (client should not receive this)");
                        }
                        _ => tracing::warn!("Unexpected message type: {:?}", parsed),
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }

        Ok(())
    }
}
