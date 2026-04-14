use bitwarden_threading::{
    ThreadBoundRunner,
    cancellation_token::wasm::{AbortController, AbortControllerExt},
};
use wasm_bindgen::prelude::wasm_bindgen;

use super::drivers::{JsSharedUnlockDriver, RawJsSharedUnlockDriver};
use crate::{DeviceEvent, Follower, FollowerStartError};

/// Shared-unlock follower for WASM clients.
#[wasm_bindgen]
pub struct SharedUnlockFollower {
    follower: Follower<JsSharedUnlockDriver>,
}

#[wasm_bindgen]
impl SharedUnlockFollower {
    /// Creates a new shared-unlock follower
    #[wasm_bindgen]
    pub async fn try_new(
        ipc_client: &bitwarden_ipc::wasm::JsIpcClient,
        driver: RawJsSharedUnlockDriver,
    ) -> Result<Self, bitwarden_ipc::SubscribeError> {
        let runner = ThreadBoundRunner::new(driver);
        let driver = JsSharedUnlockDriver::new(runner);
        let follower = Follower::create(driver, ipc_client.client.clone()).await;

        Ok(Self { follower })
    }

    /// Starts the shared-unlock follower, which listens for messages from the leader and handles
    /// them accordingly. The follower will also send heartbeat messages to the leader at
    /// regular intervals to keep the shared session active.
    #[wasm_bindgen]
    pub async fn start(
        &self,
        abort_controller: Option<AbortController>,
    ) -> Result<(), FollowerStartError> {
        self.follower
            .start(abort_controller.map(|abort| abort.to_cancellation_token()))
            .await
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
}
