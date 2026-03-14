use std::sync::{Arc, Mutex};

use bitwarden_core::UserId;
use bitwarden_encoding::B64;
use bitwarden_ipc::{Endpoint, OutgoingMessage};
use bitwarden_threading::cancellation_token::CancellationToken;
use tracing::info;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};
use wasm_bindgen_futures::{js_sys, spawn_local};

use crate::shared_unlock::{
    lock_management::{LockState, UserLockManagement},
    protocol::{DeviceEvents, Leader, LeaderDiscovery, Message, MessageSender},
};

#[wasm_bindgen]
extern "C" {
    pub type WasmUserLockManagement;

    #[wasm_bindgen(method, catch)]
    async fn lock_user(this: &WasmUserLockManagement, user_id: UserId) -> Result<(), JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn unlock_user(
        this: &WasmUserLockManagement,
        user_id: UserId,
        user_key: Vec<u8>,
    ) -> Result<(), JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn list_users(this: &WasmUserLockManagement) -> Result<js_sys::Array, JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn get_user_key(
        this: &WasmUserLockManagement,
        user_id: UserId,
    ) -> Result<JsValue, JsValue>;
}

struct InternalWasmUserLockManagement {
    inner: WasmUserLockManagement,
}

impl UserLockManagement for InternalWasmUserLockManagement {
    async fn lock_user(&self, user_id: UserId) -> Result<(), ()> {
        self.inner.lock_user(user_id).await.map_err(|_| ())
    }

    async fn unlock_user(&self, user_id: UserId, user_key: Vec<u8>) -> Result<(), ()> {
        self.inner
            .unlock_user(user_id, user_key)
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
            Some(key) => LockState::Unlocked {
                key: B64::try_from(key)
                    .map(|b64| b64.as_bytes().to_vec())
                    .unwrap_or_default(),
            },
            None => LockState::Locked,
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
    fn send_message(&self, message: crate::shared_unlock::protocol::Message, recipient: Endpoint) {
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
        super::protocol::Follower<InternalWasmUserLockManagement, WasmSender, WasmLeaderDiscovery>,
    >,
}

#[wasm_bindgen]
pub struct SharedUnlockLeader {
    subscription: Arc<Mutex<bitwarden_ipc::wasm::JsIpcClientSubscription>>,
    cancellation_token: CancellationToken,
    leader: Arc<Leader<InternalWasmUserLockManagement, WasmSender>>,
}

pub struct WasmLeaderDiscovery {}

impl LeaderDiscovery for WasmLeaderDiscovery {
    async fn discover_leader(&self) -> Option<Endpoint> {
        Some(Endpoint::BrowserBackground)
    }
}

#[wasm_bindgen]
impl SharedUnlockFollower {
    #[wasm_bindgen]
    pub async fn try_new(
        ipc_client: &bitwarden_ipc::wasm::JsIpcClient,
        lock_management: WasmUserLockManagement,
    ) -> Result<Self, bitwarden_ipc::SubscribeError> {
        let cancellation_token = CancellationToken::new();
        let subscription = ipc_client.subscribe().await?;
        let follower = super::protocol::Follower::create(
            InternalWasmUserLockManagement {
                inner: lock_management,
            },
            WasmLeaderDiscovery {},
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
                        let mut subscription = match subscription.lock() {
                            Ok(guard) => guard,
                            Err(poisoned) => poisoned.into_inner(),
                        };
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
    }

    #[wasm_bindgen]
    pub async fn handle_device_event(
        &self,
        event: DeviceEvents,
        ipc_client: &bitwarden_ipc::wasm::JsIpcClient,
    ) {
        let wasm_sender = WasmSender::new(ipc_client);
        if let Err(error) = self.follower.handle_device_event(event, wasm_sender).await {
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
        lock_management: WasmUserLockManagement,
    ) -> Result<Self, bitwarden_ipc::SubscribeError> {
        let internal_lock_management = InternalWasmUserLockManagement {
            inner: lock_management,
        };
        let users = internal_lock_management.list_users().await;
        tracing::info!("SharedUnlockLeader: Found users: {:?}", users);
        let cancellation_token = CancellationToken::new();
        let subscription = ipc_client.subscribe().await?;
        let leader = Leader::create(internal_lock_management, WasmSender::new(ipc_client));

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
                        let mut subscription = subscription.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                        subscription.receive(None).await
                    } => {
                        match result {
                            Ok(incoming_message) => {
                                info!("Incoming message from {:?}: {:?}", incoming_message.source, incoming_message.payload);
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
    pub fn stop(&self) {
        self.cancellation_token.cancel();
    }
}
