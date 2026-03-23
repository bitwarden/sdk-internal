use std::sync::Arc;

use bitwarden_core::UserId;
use bitwarden_encoding::B64;
use bitwarden_ipc::Endpoint;
use tracing::info;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};
use wasm_bindgen_futures::js_sys;

use crate::{
    HEARTBEAT_INTERVAL, HeartbeatResponseHandler, LeaderDiscovery, LockState, UserKey,
    UserLockManagement,
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

pub(super) struct WasmSharedUnlockDriver {
    pub(super) inner: Arc<WasmDriverModule>,
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

pub(super) struct WasmDriverHeartbeatResponseHandler {
    pub(super) inner: Arc<WasmDriverModule>,
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

pub(super) struct WasmDriverLeaderDiscovery {
    pub(super) inner: Arc<WasmDriverModule>,
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
