use bitwarden_threading::{
    ThreadBoundRunner,
    cancellation_token::wasm::{AbortController, AbortControllerExt},
};
use wasm_bindgen::prelude::wasm_bindgen;

use super::drivers::{JsUserLockManagement, RawJsUserLockManagement};
use crate::{DeviceEvent, Leader, LeaderStartError};

/// Shared-unlock leader for WASM clients.
#[wasm_bindgen]
pub struct SharedUnlockLeader {
    leader: Leader<JsUserLockManagement>,
}

#[wasm_bindgen]
impl SharedUnlockLeader {
    /// Creates a new shared-unlock leader
    #[wasm_bindgen]
    pub async fn try_new(
        ipc_client: &bitwarden_ipc::wasm::JsIpcClient,
        lock_management: RawJsUserLockManagement,
    ) -> Result<Self, bitwarden_ipc::SubscribeError> {
        let runner = ThreadBoundRunner::new(lock_management);
        let lock_management = JsUserLockManagement::new(runner);
        let leader = Leader::create(lock_management, ipc_client.client.clone());

        Ok(Self { leader })
    }

    /// Starts background processing for incoming follower-to-leader IPC messages.
    #[wasm_bindgen]
    pub async fn start(
        &self,
        abort_controller: Option<AbortController>,
    ) -> Result<(), LeaderStartError> {
        self.leader
            .start(abort_controller.map(|abort| abort.to_cancellation_token()))
            .await
    }

    /// Forwards a device event to the shared-unlock leader implementation
    #[wasm_bindgen]
    pub async fn handle_device_event(&self, event: DeviceEvent) {
        if let Err(error) = self.leader.handle_device_event(event).await {
            tracing::error!(?error, "Failed to handle shared unlock leader device event");
        }
    }
}
