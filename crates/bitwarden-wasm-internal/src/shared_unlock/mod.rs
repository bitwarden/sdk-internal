use std::sync::Arc;

mod lock_management;
mod protocol;
mod wasm;

use bitwarden_core::UserId;
use bitwarden_threading::cancellation_token::CancellationToken;
use tokio::sync::Mutex;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::spawn_local;

use crate::client::PasswordManagerClientRepository;

#[wasm_bindgen]
pub struct SharedUnlockFollower {
    subscription: Arc<Mutex<bitwarden_ipc::wasm::JsIpcClientSubscription>>,
    cancellation_token: CancellationToken,
}

#[wasm_bindgen]
impl SharedUnlockFollower {
    #[wasm_bindgen]
    pub async fn create(
        ipc_client: &bitwarden_ipc::wasm::JsIpcClient,
    ) -> Result<Self, bitwarden_ipc::SubscribeError> {
        let cancellation_token = CancellationToken::new();
        let subscription = ipc_client.subscribe().await?;

        Ok(Self {
            subscription: Arc::new(Mutex::new(subscription)),
            cancellation_token,
        })
    }

    #[wasm_bindgen]
    pub fn start(
        &self,
        repository: PasswordManagerClientRepository,
        user_lock_management: &WasmUserLockManagement,
    ) {
        let cancellation_token = self.cancellation_token.clone();
        let subscription = Arc::clone(&self.subscription);

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
                            Ok(message) => {
                                if let Err(error) = repository.handle_ipc_message(message.into()).await {
                                    tracing::error!(?error, "Failed to handle shared unlock IPC message");
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
