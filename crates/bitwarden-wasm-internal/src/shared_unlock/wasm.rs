use std::sync::Arc;

use bitwarden_core::UserId;
use bitwarden_encoding::B64;
use bitwarden_ipc::{Endpoint, OutgoingMessage};
use bitwarden_threading::cancellation_token::CancellationToken;
use tokio::sync::Mutex;
use tracing::info;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};
use wasm_bindgen_futures::{js_sys, spawn_local};

use crate::shared_unlock::protocol::{
    DeviceEvent, Follower, HEARTBEAT_INTERVAL, HeartbeatResponseHandler, Leader, LeaderDiscovery,
    LockState, Message, MessageSender, UserKey, UserLockManagement,
};

#[wasm_bindgen]
extern "C" {
    pub type WasmDriverModule;

    #[wasm_bindgen(method, catch)]
    async fn lock_user(this: &WasmDriverModule, user_id: UserId) -> Result<(), JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn unlock_user(
        this: &WasmDriverModule,
        user_id: UserId,
        user_key: Vec<u8>,
    ) -> Result<(), JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn list_users(this: &WasmDriverModule) -> Result<js_sys::Array, JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn get_user_key(this: &WasmDriverModule, user_id: UserId) -> Result<JsValue, JsValue>;

    /// Supress the vault timeout until the given timestamp (in milliseconds since unix epoch).
    #[wasm_bindgen(method, catch)]
    async fn suppress_vault_timeout(this: &WasmDriverModule, until: f64) -> Result<(), JsValue>;

    /// Get the client type of the current device
    #[wasm_bindgen(method, catch)]
    async fn get_client_name(this: &WasmDriverModule) -> Result<JsValue, JsValue>;
}

struct WasmSharedUnlockDriver {
    inner: Arc<WasmDriverModule>,
}

impl UserLockManagement for WasmSharedUnlockDriver {
    async fn lock_user(&self, user_id: UserId) -> Result<(), ()> {
        self.inner.lock_user(user_id).await.map_err(|_| ())
    }

    async fn unlock_user(&self, user_id: UserId, user_key: UserKey) -> Result<(), ()> {
        self.inner
            .unlock_user(user_id, user_key.as_bytes().to_vec())
            .await
            .map_err(|_| ())
    }

    async fn list_users(&self) -> Vec<UserId> {
        match self.inner.list_users().await {
            Ok(array) => array
                .iter()
                .filter_map(|js_value| js_value.as_string())
                .filter_map(|s| s.parse().ok())
                .collect(),
            Err(_) => vec![],
        }
    }

    async fn get_user_lock_state(&self, user_id: UserId) -> LockState {
        match self
            .inner
            .get_user_key(user_id)
            .await
            .ok()
            .and_then(|js_value| js_value.as_string())
        {
            Some(user_key_b64) => match B64::try_from(user_key_b64.as_str()) {
                Ok(user_key) => LockState::Unlocked {
                    user_key: UserKey::from_bytes(user_key.into_bytes()),
                },
                Err(_) => LockState::Locked,
            },
            None => LockState::Locked,
        }
    }
}

struct WasmDriverHeartbeatResponseHandler {
    inner: Arc<WasmDriverModule>,
}

impl HeartbeatResponseHandler for WasmDriverHeartbeatResponseHandler {
    async fn handle_heartbeat(&self, _user_id: UserId) {
        info!("Received shared unlock heartbeat response for user_id:");
        // Shared unlock heartbeat responses are acknowledged by keeping the session active.
        // We can suppress the vault timeout until the next expected heartbeat to achieve this.
        let until = js_sys::Date::now() + HEARTBEAT_INTERVAL.as_millis() as f64;
        if let Err(error) = self.inner.suppress_vault_timeout(until).await {
            tracing::error!(?error, "Failed to supress vault timeout on heartbeat");
        }
    }
}

struct WasmDriverLeaderDiscovery {
    inner: Arc<WasmDriverModule>,
}

impl LeaderDiscovery for WasmDriverLeaderDiscovery {
    async fn discover_leader(&self) -> Option<Endpoint> {
        let client_name = match self.inner.get_client_name().await {
            Ok(name) => name.as_string()?,
            Err(_) => return None,
        };
        match client_name.as_str() {
            "web" => Some(Endpoint::BrowserBackground),
            "browser" => Some(Endpoint::DesktopMain),
            "cli" => Some(Endpoint::DesktopMain),
            _ => None,
        }
    }
}

fn clone_ipc_client(
    ipc_client: &bitwarden_ipc::wasm::JsIpcClient,
) -> bitwarden_ipc::wasm::JsIpcClient {
    bitwarden_ipc::wasm::JsIpcClient {
        client: Arc::clone(&ipc_client.client),
    }
}

struct WasmSender {
    ipc_client: bitwarden_ipc::wasm::JsIpcClient,
}

impl WasmSender {
    fn new(ipc_client: &bitwarden_ipc::wasm::JsIpcClient) -> Self {
        Self {
            ipc_client: clone_ipc_client(ipc_client),
        }
    }
}

impl Clone for WasmSender {
    fn clone(&self) -> Self {
        Self {
            ipc_client: clone_ipc_client(&self.ipc_client),
        }
    }
}

impl MessageSender for WasmSender {
    fn send_message(&self, message: Message, recipient: Endpoint) {
        let payload = match message.to_cbor() {
            Ok(payload) => payload,
            Err(error) => {
                tracing::error!(?error, "Failed to serialize shared unlock IPC message");
                return;
            }
        };

        let outgoing_message = OutgoingMessage {
            payload,
            destination: recipient,
            topic: Some("password-manager.shared-unlock".to_string()),
        };

        let ipc_client = clone_ipc_client(&self.ipc_client);

        spawn_local(async move {
            if let Err(error) = ipc_client.send(outgoing_message).await {
                tracing::error!(?error, "Failed to send shared unlock IPC message");
            }
        });
    }
}

#[wasm_bindgen]
pub struct SharedUnlockFollower {
    subscription: Arc<Mutex<bitwarden_ipc::wasm::JsIpcClientSubscription>>,
    cancellation_token: CancellationToken,
    follower: Arc<
        Follower<
            WasmSharedUnlockDriver,
            WasmSender,
            WasmDriverLeaderDiscovery,
            WasmDriverHeartbeatResponseHandler,
        >,
    >,
}

#[wasm_bindgen]
pub struct SharedUnlockLeader {
    subscription: Arc<Mutex<bitwarden_ipc::wasm::JsIpcClientSubscription>>,
    cancellation_token: CancellationToken,
    leader: Arc<Leader<WasmSharedUnlockDriver, WasmSender>>,
}

#[wasm_bindgen]
impl SharedUnlockFollower {
    #[wasm_bindgen]
    pub async fn try_new(
        ipc_client: &bitwarden_ipc::wasm::JsIpcClient,
        lock_management: WasmDriverModule,
    ) -> Result<Self, bitwarden_ipc::SubscribeError> {
        let cancellation_token = CancellationToken::new();
        let subscription = ipc_client.subscribe().await?;
        let sender = WasmSender::new(ipc_client);
        let driver = Arc::new(lock_management);
        let lock_management = WasmSharedUnlockDriver {
            inner: Arc::clone(&driver),
        };
        let leader_discovery = WasmDriverLeaderDiscovery {
            inner: Arc::clone(&driver),
        };
        let heartbeat_response_handler = WasmDriverHeartbeatResponseHandler { inner: driver };
        let follower = Follower::create(
            lock_management,
            leader_discovery,
            heartbeat_response_handler,
            sender,
        )
        .await;

        Ok(Self {
            subscription: Arc::new(Mutex::new(subscription)),
            cancellation_token,
            follower: Arc::new(follower),
        })
    }

    #[wasm_bindgen]
    pub fn start(&self) {
        let cancellation_token = self.cancellation_token.clone();
        let subscription = Arc::clone(&self.subscription);
        let follower = Arc::clone(&self.follower);

        spawn_local(async move {
            loop {
                tokio::select! {
                    _ = cancellation_token.cancelled() => {
                        tracing::debug!("Shared unlock follower cancelled");
                        break;
                    }
                    result = async {
                        let mut subscription = subscription.lock().await;
                        subscription.receive(None).await
                    } => {
                        match result {
                            Ok(incoming_message) => {
                                match Message::from_cbor(incoming_message.payload.as_slice()) {
                                    Ok(message) => {
                                        if let Err(error) = follower.receive_message(message).await {
                                            tracing::error!(?error, "Failed to handle shared unlock follower message");
                                        }
                                    }
                                    Err(error) => {
                                        tracing::error!(?error, "Failed to decode shared unlock follower IPC message");
                                    }
                                }
                            }
                            Err(error) => {
                                tracing::error!(?error, "Failed to receive shared unlock IPC message");
                                break;
                            }
                        }
                    }
                }
            }
        });

        let cancellation_token = self.cancellation_token.clone();
        let follower = Arc::clone(&self.follower);
        spawn_local(async move {
            loop {
                tokio::select! {
                    _ = cancellation_token.cancelled() => {
                        tracing::debug!("Shared unlock follower timer cancelled");
                        break;
                    }
                    _ = wasmtimer::tokio::sleep(HEARTBEAT_INTERVAL) => {
                        if let Err(error) = follower.handle_device_event(DeviceEvent::Timer).await {
                            tracing::error!(?error, "Failed to handle shared unlock follower timer event");
                        }
                    }
                }
            }
        });
    }

    #[wasm_bindgen]
    pub async fn handle_device_event(&self, event: DeviceEvent) {
        if let Err(error) = self.follower.handle_device_event(event).await {
            tracing::error!(
                ?error,
                "Failed to handle shared unlock follower device event"
            );
        }
    }

    #[wasm_bindgen]
    pub fn stop(&self) {
        self.cancellation_token.cancel();
    }
}

#[wasm_bindgen]
impl SharedUnlockLeader {
    #[wasm_bindgen]
    pub async fn try_new(
        ipc_client: &bitwarden_ipc::wasm::JsIpcClient,
        lock_management: WasmDriverModule,
    ) -> Result<Self, bitwarden_ipc::SubscribeError> {
        let lock_management = WasmSharedUnlockDriver {
            inner: Arc::new(lock_management),
        };
        let cancellation_token = CancellationToken::new();
        let subscription = ipc_client.subscribe().await?;
        let leader = Leader::create(lock_management, WasmSender::new(ipc_client));

        Ok(Self {
            subscription: Arc::new(Mutex::new(subscription)),
            cancellation_token,
            leader: Arc::new(leader),
        })
    }

    #[wasm_bindgen]
    pub fn start(&self) {
        let cancellation_token = self.cancellation_token.clone();
        let subscription = Arc::clone(&self.subscription);
        let leader = Arc::clone(&self.leader);

        spawn_local(async move {
            loop {
                tokio::select! {
                    _ = cancellation_token.cancelled() => {
                        tracing::debug!("Shared unlock leader cancelled");
                        break;
                    }
                    result = async {
                        let mut subscription = subscription.lock().await;
                        subscription.receive(None).await
                    } => {
                        match result {
                            Ok(incoming_message) => {
                                let source = incoming_message.source;
                                match Message::from_cbor(incoming_message.payload.as_slice()) {
                                    Ok(message) => {
                                        if let Err(error) = leader.receive_message(message, source).await {
                                            tracing::error!(?error, "Failed to handle shared unlock leader message");
                                        }
                                    }
                                    Err(error) => {
                                        tracing::error!(?error, "Failed to decode shared unlock leader IPC message");
                                    }
                                }
                            }
                            Err(error) => {
                                tracing::error!(?error, "Failed to receive shared unlock IPC message");
                                break;
                            }
                        }
                    }
                }
            }
        });
    }

    #[wasm_bindgen]
    pub fn handle_device_event(&self, event: DeviceEvent) {
        if let Err(error) = self.leader.handle_device_event(event) {
            tracing::error!(?error, "Failed to handle shared unlock leader device event");
        }
    }

    #[wasm_bindgen]
    pub fn stop(&self) {
        self.cancellation_token.cancel();
    }
}
