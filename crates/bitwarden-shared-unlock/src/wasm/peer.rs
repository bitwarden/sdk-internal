use bitwarden_threading::cancellation_token::wasm::{AbortController, AbortControllerExt};
use wasm_bindgen::prelude::wasm_bindgen;

use super::drivers::{JsSharedUnlockDriver, RawJsSharedUnlockDriver};
use crate::{DeviceEvent, PeerStartError, SharedUnlockClient, SharedUnlockPeer as Peer};

/// Shared-unlock peer for WASM clients.
#[wasm_bindgen]
pub struct SharedUnlockPeer {
    peer: Peer<JsSharedUnlockDriver>,
}

#[wasm_bindgen]
impl SharedUnlockPeer {
    /// Creates a new shared-unlock peer
    #[wasm_bindgen(constructor)]
    pub fn new(
        ipc_client: &bitwarden_ipc::wasm::JsIpcClient,
        driver: RawJsSharedUnlockDriver,
    ) -> Self {
        let driver = JsSharedUnlockDriver::new(driver);
        let peer = Peer::create(driver, ipc_client.client.clone());
        Self { peer }
    }

    /// Sets which clients this peer shares unlock state with. Defaults to none.
    #[wasm_bindgen]
    pub fn set_destinations(&self, destinations: Vec<SharedUnlockClient>) {
        self.peer.set_destinations(destinations);
    }

    /// Starts the shared-unlock peer
    #[wasm_bindgen]
    pub async fn start(
        &self,
        abort_controller: Option<AbortController>,
    ) -> Result<(), PeerStartError> {
        self.peer
            .start(abort_controller.map(|abort| abort.to_cancellation_token()))
            .await
    }

    /// Forwards a device event to the shared-unlock peer state machine.
    #[wasm_bindgen]
    pub async fn handle_device_event(&self, event: DeviceEvent) {
        if let Err(error) = self.peer.handle_device_event(event).await {
            tracing::error!(?error, "Failed to handle shared unlock device event");
        }
    }
}
