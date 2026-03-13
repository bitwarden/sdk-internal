use std::sync::{Arc, Mutex};

use bitwarden_core::UserId;
use bitwarden_encoding::B64;
use bitwarden_threading::cancellation_token::CancellationToken;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};
use wasm_bindgen_futures::js_sys;

use crate::shared_unlock::{
    lock_management::{LockState, UserLockManagement},
    protocol::{DeviceEvents, LeaderDiscovery, Message, MessageSender},
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

struct WasmSender<'a> {
    ipc_client: &'a bitwarden_ipc::wasm::JsIpcClient,
}

impl<'a> WasmSender<'a> {
    fn new(ipc_client: &'a bitwarden_ipc::wasm::JsIpcClient) -> Self {
        Self { ipc_client }
    }
}

impl<'a> MessageSender for WasmSender<'a> {
    fn send_message(
        &self,
        _message: crate::shared_unlock::protocol::Message,
        _recipient: bitwarden_ipc::Endpoint,
    ) {
    }
}

#[wasm_bindgen]
pub struct SharedUnlockFollower {
    subscription: Arc<Mutex<bitwarden_ipc::wasm::JsIpcClientSubscription>>,
    cancellation_token: CancellationToken,
    follower: Arc<
        super::protocol::Follower<
            InternalWasmUserLockManagement,
            WasmSender<'static>,
            WasmLeaderDiscovery,
        >,
    >,
}

pub struct WasmLeaderDiscovery {}

impl LeaderDiscovery for WasmLeaderDiscovery {
    async fn discover_leader(&self) -> Option<bitwarden_ipc::Endpoint> {
        Some(bitwarden_ipc::Endpoint::BrowserBackground)
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

        wasm_bindgen_futures::spawn_local(async move {
            loop {
                tokio::select! {
                    _ = cancellation_token.cancelled() => {
                        tracing::debug!("Shared unlock follower cancelled");
                        break;
                    }
                    result = async {
                        let mut subscription = subscription.lock().unwrap();
                        subscription.receive(None).await
                    } => {
                        match result {
                            Ok(message) => {
                                let p = message.payload;
                                let message = Message::from_cbor(p.as_slice()).unwrap();
                                follower.receive_message(message).await.unwrap_or_else(|e| {
                                    tracing::error!(?e, "Failed to handle shared unlock IPC message");
                                });
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
        ipc_clietnt: &bitwarden_ipc::wasm::JsIpcClient,
    ) {
        let wasm_sender = WasmSender::new(ipc_clietnt);
        self.follower
            .handle_device_event(event, wasm_sender)
            .await
            .unwrap();
    }

    #[wasm_bindgen]
    pub fn stop(&self) {
        self.cancellation_token.cancel();
    }
}
