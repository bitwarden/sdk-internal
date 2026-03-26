use bitwarden_core::UserId;
use bitwarden_encoding::B64;
use bitwarden_ipc::{Endpoint, HostId};
use bitwarden_threading::ThreadBoundRunner;
use tracing::info;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};
use wasm_bindgen_futures::js_sys;

use crate::{
    HEARTBEAT_INTERVAL, HeartbeatResponseHandler, LeaderDiscovery, LockState, UserKey,
    UserLockManagement,
};

#[wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export interface UserLockManagement {
    lock_user(user_id: UserId): Promise<void>;
    unlock_user(user_id: UserId, user_key: Uint8Array): Promise<void>;
    list_users(): Promise<UserId[]>;
    get_user_key(user_id: UserId): Promise<string | undefined>;
    suppress_vault_timeout(until: number): Promise<void>;
    get_client_name(): Promise<string>;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = UserLockManagement, typescript_type = "UserLockManagement")]
    pub type RawJsUserLockManagement;

    #[wasm_bindgen(method, catch)]
    async fn lock_user(this: &RawJsUserLockManagement, user_id: UserId) -> Result<(), JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn unlock_user(
        this: &RawJsUserLockManagement,
        user_id: UserId,
        user_key: Box<[u8]>,
    ) -> Result<(), JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn list_users(this: &RawJsUserLockManagement) -> Result<js_sys::Array, JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn get_user_key(
        this: &RawJsUserLockManagement,
        user_id: UserId,
    ) -> Result<JsValue, JsValue>;

    /// Supress the vault timeout until the given timestamp (in milliseconds since unix epoch).
    #[wasm_bindgen(method, catch)]
    async fn suppress_vault_timeout(
        this: &RawJsUserLockManagement,
        until: f64,
    ) -> Result<(), JsValue>;

    /// Get the client type of the current device
    #[wasm_bindgen(method, catch)]
    async fn get_client_name(this: &RawJsUserLockManagement) -> Result<JsValue, JsValue>;
}

pub(super) struct JsUserLockManagement {
    runner: ThreadBoundRunner<RawJsUserLockManagement>,
}

impl JsUserLockManagement {
    pub(super) fn new(runner: ThreadBoundRunner<RawJsUserLockManagement>) -> Self {
        Self { runner }
    }
}

impl UserLockManagement for JsUserLockManagement {
    async fn lock_user(&self, user_id: UserId) -> Result<(), ()> {
        self.runner
            .run_in_thread(
                move |driver| async move { driver.lock_user(user_id).await.map_err(|_| ()) },
            )
            .await
            .map_err(|_| ())?
    }

    async fn unlock_user(&self, user_id: UserId, user_key: UserKey) -> Result<(), ()> {
        self.runner
            .run_in_thread(move |driver| async move {
                driver
                    .unlock_user(user_id, user_key.as_bytes().into())
                    .await
                    .map_err(|_| ())
            })
            .await
            .map_err(|_| ())?
    }

    async fn list_users(&self) -> Vec<UserId> {
        self.runner
            .run_in_thread(move |driver| async move {
                match driver.list_users().await {
                    Ok(array) => array
                        .iter()
                        .filter_map(|js_value| js_value.as_string())
                        .filter_map(|s| s.parse().ok())
                        .collect(),
                    Err(_) => vec![],
                }
            })
            .await
            .unwrap_or_default()
    }

    async fn get_user_lock_state(&self, user_id: UserId) -> LockState {
        self.runner
            .run_in_thread(move |driver| async move {
                match driver
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
            })
            .await
            .unwrap_or(LockState::Locked)
    }
}

pub(super) struct WasmDriverHeartbeatResponseHandler {
    runner: ThreadBoundRunner<RawJsUserLockManagement>,
}

impl WasmDriverHeartbeatResponseHandler {
    pub(super) fn new(runner: ThreadBoundRunner<RawJsUserLockManagement>) -> Self {
        Self { runner }
    }
}

impl HeartbeatResponseHandler for WasmDriverHeartbeatResponseHandler {
    async fn handle_heartbeat(&self, _user_id: UserId) {
        info!("Received shared unlock heartbeat response for user_id:");
        // Shared unlock heartbeat responses are acknowledged by keeping the session active.
        // We can suppress the vault timeout until the next expected heartbeat to achieve this.
        let until = js_sys::Date::now() + HEARTBEAT_INTERVAL.as_millis() as f64;
        let result = self
            .runner
            .run_in_thread(move |driver| async move { driver.suppress_vault_timeout(until).await })
            .await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::error!(?error, "Failed to supress vault timeout on heartbeat")
            }
            Err(error) => {
                tracing::error!(?error, "Failed to supress vault timeout on heartbeat")
            }
        }
    }
}

pub(super) struct JsLeaderDiscovery {
    runner: ThreadBoundRunner<RawJsUserLockManagement>,
}

impl JsLeaderDiscovery {
    pub(super) fn new(runner: ThreadBoundRunner<RawJsUserLockManagement>) -> Self {
        Self { runner }
    }
}

impl LeaderDiscovery for JsLeaderDiscovery {
    async fn discover_leader(&self) -> Option<Endpoint> {
        self.runner
            .run_in_thread(move |driver| async move {
                let client_name = match driver.get_client_name().await {
                    Ok(name) => name.as_string()?,
                    Err(_) => return None,
                };
                match client_name.as_str() {
                    "web" => Some(Endpoint::BrowserBackground { id: HostId::Own }),
                    "browser" => Some(Endpoint::DesktopRenderer),
                    "cli" => Some(Endpoint::DesktopRenderer),
                    _ => None,
                }
            })
            .await
            .ok()
            .flatten()
    }
}
