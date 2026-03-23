use std::sync::Arc;

use bitwarden_threading::cancellation_token::CancellationToken;
use tokio::sync::Mutex;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen_futures::spawn_local;

use super::{
    drivers::{
        WasmDriverHeartbeatResponseHandler, WasmDriverLeaderDiscovery, WasmDriverModule,
        WasmSharedUnlockDriver,
    },
    sender::WasmSender,
};
use crate::{DeviceEvent, Follower, HEARTBEAT_INTERVAL, Message};

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
