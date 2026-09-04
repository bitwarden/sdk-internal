use bitwarden_core::UserId;
use bitwarden_crypto::SymmetricCryptoKey;
use bitwarden_ffi::Ts;
use bitwarden_ipc::{Endpoint, HostId};
use bitwarden_threading::ThreadBoundRunner;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};
use wasm_bindgen_futures::js_sys;

use crate::SharedUnlockDriver;

#[wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export interface SharedUnlockDriver {
    lock_user(user_id: UserId): Promise<void>;
    unlock_user(user_id: UserId, user_key: SymmetricKey): Promise<void>;
    list_users(): Promise<UserId[]>;
    suppress_vault_timeout(user_id: UserId, suppression_duration: number): Promise<void>;
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
    async fn lock_user(this: &RawJsSharedUnlockDriver, user_id: Ts<UserId>) -> Result<(), JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn unlock_user(
        this: &RawJsSharedUnlockDriver,
        user_id: Ts<UserId>,
        user_key: SymmetricCryptoKey,
    ) -> Result<(), JsValue>;
    #[wasm_bindgen(method, catch)]
    async fn list_users(this: &RawJsSharedUnlockDriver) -> Result<js_sys::Array, JsValue>;

    /// Supress the vault timeout for the given duration (in milliseconds).
    #[wasm_bindgen(method, catch)]
    async fn suppress_vault_timeout(
        this: &RawJsSharedUnlockDriver,
        user_id: Ts<UserId>,
        suppression_duration: f64,
    ) -> Result<(), JsValue>;

    /// Get the client type of the current device
    #[wasm_bindgen(method, catch)]
    async fn get_client_name(this: &RawJsSharedUnlockDriver) -> Result<JsValue, JsValue>;

    /// Get vault URL for the user with the given ID, if available. This is used to verify IPC
    /// message sources.
    #[wasm_bindgen(method, catch)]
    async fn get_vault_url(
        this: &RawJsSharedUnlockDriver,
        user_id: Ts<UserId>,
    ) -> Result<JsValue, JsValue>;
}

bitwarden_ffi::impl_wire_object!(RawJsSharedUnlockDriver);

pub(super) struct JsSharedUnlockDriver {
    runner: ThreadBoundRunner<RawJsSharedUnlockDriver>,
}

impl JsSharedUnlockDriver {
    pub(super) fn new(driver: RawJsSharedUnlockDriver) -> Self {
        Self {
            runner: ThreadBoundRunner::new(driver),
        }
    }
}

async fn list_users(driver: &RawJsSharedUnlockDriver) -> Vec<UserId> {
    match driver.list_users().await {
        Ok(array) => array
            .iter()
            .filter_map(|js_value| js_value.as_string())
            .filter_map(|s| s.parse().ok())
            .collect(),
        Err(error) => {
            tracing::error!(?error, "Failed to list users");
            vec![]
        }
    }
}

#[async_trait::async_trait]
impl SharedUnlockDriver for JsSharedUnlockDriver {
    async fn lock_user(&self, user_id: UserId) -> Result<(), ()> {
        self.runner
            .run_in_thread(move |driver| async move {
                let user_id = Ts::from_rust(&user_id).map_err(|_| ())?;
                driver.lock_user(user_id).await.map_err(|_| ())
            })
            .await
            .map_err(|_| ())?
    }

    async fn unlock_user(&self, user_id: UserId, user_key: SymmetricCryptoKey) -> Result<(), ()> {
        self.runner
            .run_in_thread(move |driver| async move {
                let user_id = Ts::from_rust(&user_id).map_err(|_| ())?;
                driver.unlock_user(user_id, user_key).await.map_err(|_| ())
            })
            .await
            .map_err(|_| ())?
    }

    async fn list_users(&self) -> Vec<UserId> {
        self.runner
            .run_in_thread(move |driver| async move { list_users(&driver).await })
            .await
            .unwrap_or_default()
    }

    async fn get_vault_url(&self, user_id: UserId) -> Option<String> {
        self.runner
            .run_in_thread(move |driver| async move {
                driver
                    .get_vault_url(Ts::from_rust(&user_id).ok()?)
                    .await
                    .ok()
                    .and_then(|js_value| js_value.as_string())
            })
            .await
            .ok()
            .flatten()
    }

    async fn suppress_vault_timeout(
        &self,
        user_id: UserId,
        suppression_duration: std::time::Duration,
    ) {
        let result = self
            .runner
            .run_in_thread(move |driver| async move {
                let user_id = Ts::from_rust(&user_id).map_err(|_| JsValue::UNDEFINED)?;
                driver
                    .suppress_vault_timeout(user_id, suppression_duration.as_millis() as f64)
                    .await
            })
            .await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::error!(
                    ?error,
                    "Failed to suppress vault timeout for user_id: {}",
                    user_id
                )
            }
            Err(error) => {
                tracing::error!(
                    ?error,
                    "Failed to suppress vault timeout for user_id: {}",
                    user_id
                )
            }
        }
    }

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
