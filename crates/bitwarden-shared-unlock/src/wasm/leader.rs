use std::sync::Arc;

use bitwarden_threading::cancellation_token::CancellationToken;
use tokio::sync::Mutex;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen_futures::spawn_local;

use super::{
    drivers::{WasmDriverModule, WasmSharedUnlockDriver},
    sender::WasmSender,
};
use crate::{DeviceEvent, Leader, Message};

#[wasm_bindgen]
pub struct SharedUnlockLeader {
    subscription: Arc<Mutex<bitwarden_ipc::wasm::JsIpcClientSubscription>>,
    cancellation_token: CancellationToken,
    leader: Arc<Leader<WasmSharedUnlockDriver, WasmSender>>,
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
