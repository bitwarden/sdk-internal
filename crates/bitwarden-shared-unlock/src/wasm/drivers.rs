use bitwarden_core::UserId;
use bitwarden_crypto::SymmetricCryptoKey;
use bitwarden_ipc::{Endpoint, HostId};
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};
use wasm_bindgen_futures::js_sys;

use crate::{LockState, SharedUnlockDriver};

#[wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export interface SharedUnlockDriver {
    lock_user(user_id: UserId): Promise<void>;
    unlock_user(user_id: UserId, user_key: SymmetricKey): Promise<void>;
    list_users(): Promise<UserId[]>;
    get_user_key(user_id: UserId): Promise<SymmetricKey | undefined>;
    suppress_vault_timeout(suppression_duration: number, userId: UserId): Promise<void>;
    get_client_name(): Promise<string>;
    get_vault_url(user_id: UserId): Promise<string | undefined>;
}
"#;

#[wasm_bindgen]
extern "C" {
    /// JavaScript implementation of shared unlock operations used by shared unlock protocol.
    #[wasm_bindgen(js_name = SharedUnlockDriver, typescript_type = "SharedUnlockDriver")]
    pub type RawJsSharedUnlockDriver;

    #[wasm_bindgen(method, catch)]
    async fn lock_user(this: &RawJsSharedUnlockDriver, user_id: UserId) -> Result<(), JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn unlock_user(
        this: &RawJsSharedUnlockDriver,
        user_id: UserId,
        user_key: SymmetricCryptoKey,
    ) -> Result<(), JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn list_users(this: &RawJsSharedUnlockDriver) -> Result<js_sys::Array, JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn get_user_key(
        this: &RawJsSharedUnlockDriver,
        user_id: UserId,
    ) -> Result<SymmetricCryptoKey, JsValue>;

    /// Supress the vault timeout for the given duration.
    #[wasm_bindgen(method, catch)]
    async fn suppress_vault_timeout(
        this: &RawJsSharedUnlockDriver,
        suppression_duration: f64,
        user_id: UserId,
    ) -> Result<(), JsValue>;

    /// Get the client type of the current device
    #[wasm_bindgen(method, catch)]
    async fn get_client_name(this: &RawJsSharedUnlockDriver) -> Result<JsValue, JsValue>;

    /// Get vault URL for the user with the given ID, if available. This is used to verify IPC
    /// message sources.
    #[wasm_bindgen(method, catch)]
    async fn get_vault_url(
        this: &RawJsSharedUnlockDriver,
        user_id: UserId,
    ) -> Result<JsValue, JsValue>;
}

pub(super) struct JsSharedUnlockDriver {
    driver: RawJsSharedUnlockDriver,
}

impl JsSharedUnlockDriver {
    pub(super) fn new(driver: RawJsSharedUnlockDriver) -> Self {
        Self { driver }
    }
}

#[async_trait::async_trait(?Send)]
impl SharedUnlockDriver for JsSharedUnlockDriver {
    async fn lock_user(&self, user_id: UserId) -> Result<(), ()> {
        self.driver.lock_user(user_id).await.map_err(|_| ())
    }

    async fn unlock_user(&self, user_id: UserId, user_key: SymmetricCryptoKey) -> Result<(), ()> {
        self.driver
            .unlock_user(user_id, user_key)
            .await
            .map_err(|_| ())
    }

    async fn list_users(&self) -> Vec<UserId> {
        match self.driver.list_users().await {
            Ok(array) => array
                .iter()
                .filter_map(|js_value| js_value.as_string())
                .filter_map(|s| s.parse().ok())
                .collect(),
            Err(_) => vec![],
        }
    }

    async fn get_user_lock_state(&self, user_id: UserId) -> LockState {
        match self.driver.get_user_key(user_id).await.ok() {
            Some(user_key) => LockState::Unlocked { user_key },
            None => LockState::Locked,
        }
    }

    async fn get_vault_url(&self, user_id: UserId) -> Option<String> {
        self.driver
            .get_vault_url(user_id)
            .await
            .ok()
            .and_then(|js_value| js_value.as_string())
    }

    async fn suppress_vault_timeout(
        &self,
        user_id: UserId,
        suppression_duration: std::time::Duration,
    ) {
        let result = self
            .driver
            .suppress_vault_timeout(suppression_duration.as_millis() as f64, user_id)
            .await;
        if let Err(error) = result {
            tracing::error!(
                ?error,
                "Failed to suppress vault timeout for user_id: {}",
                user_id
            )
        }
    }

    async fn discover_leader(&self) -> Option<Endpoint> {
        let client_name = match self.driver.get_client_name().await {
            Ok(name) => name.as_string()?,
            Err(_) => return None,
        };
        match client_name.as_str() {
            "web" => Some(Endpoint::BrowserBackground { id: HostId::Own }),
            "browser" => Some(Endpoint::DesktopRenderer),
            "cli" => Some(Endpoint::DesktopRenderer),
            _ => None,
        }
    }
}
