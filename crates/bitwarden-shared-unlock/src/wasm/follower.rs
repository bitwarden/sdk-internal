use std::sync::Arc;

use bitwarden_threading::{ThreadBoundRunner, cancellation_token::CancellationToken};
use tokio::sync::Mutex;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen_futures::spawn_local;

use super::drivers::{JsLeaderDiscovery, JsUserLockManagement, RawJsUserLockManagement};
use crate::{DeviceEvent, Follower, HEARTBEAT_INTERVAL, Message};

/// Shared-unlock follower for WASM clients.
#[wasm_bindgen]
pub struct SharedUnlockFollower {
    subscription: Arc<Mutex<bitwarden_ipc::wasm::JsIpcClientSubscription>>,
    cancellation_token: CancellationToken,
    follower: Arc<Follower<JsUserLockManagement, JsLeaderDiscovery>>,
}

#[wasm_bindgen]
impl SharedUnlockFollower {
    /// Creates a new shared-unlock follower
    #[wasm_bindgen]
    pub async fn try_new(
        ipc_client: &bitwarden_ipc::wasm::JsIpcClient,
        lock_management: RawJsUserLockManagement,
    ) -> Result<Self, bitwarden_ipc::SubscribeError> {
        let cancellation_token = CancellationToken::new();
        let subscription = ipc_client.subscribe().await?;
        let runner = ThreadBoundRunner::new(lock_management);
        let lock_management = JsUserLockManagement::new(runner.clone());
        let leader_discovery = JsLeaderDiscovery::new(runner.clone());
        let follower =
            Follower::create(lock_management, leader_discovery, ipc_client.client.clone()).await;

        Ok(Self {
            subscription: Arc::new(Mutex::new(subscription)),
            cancellation_token,
            follower: Arc::new(follower),
        })
    }

    /// Starts background tasks for IPC message handling and heartbeat timers.
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
                                if incoming_message.topic != Some(crate::leader::SEND_TOPIC.to_string()) {
                                    continue;
                                }
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

    /// Forwards a device event to the shared-unlock follower state machine.
    #[wasm_bindgen]
    pub async fn handle_device_event(&self, event: DeviceEvent) {
        if let Err(error) = self.follower.handle_device_event(event).await {
            tracing::error!(
                ?error,
                "Failed to handle shared unlock follower device event"
            );
        }
    }

    /// Stops background tasks started by [`SharedUnlockFollower::start`].
    #[wasm_bindgen]
    pub fn stop(&self) {
        self.cancellation_token.cancel();
    }
}
