//! WASM-specific biometrics-over-IPC. This allows clients, such as browser, CLI and web to 
//! interact with the platform biometrics system of the desktop app.
//! 
//! Note: This should eventually be moved to a bitwarden-biometrics crate that also contains implementations
//! for platform biometrics on all platforms. However, it is too early for that currently, and it is not
//! sufficiently clear what is required / how it should be structured, as it should capture the needs of
//! all platforms (mobile and web).

use bitwarden_core::UserId;
use bitwarden_ipc::{Endpoint, IpcClientExt, RequestError, RpcHandler, RpcRequest};
use bitwarden_threading::{
    ThreadBoundRunner,
    cancellation_token::wasm::{AbortSignal, AbortSignalExt},
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

#[wasm_bindgen(typescript_custom_section)]
const TS_BIOMETRICS_TYPES: &'static str = r#"
export interface BiometricsUnlock {
    /**
     * Returns the status of biometrics unlock for the given user.
     */
    get_biometrics_status(user_id: UserId): Promise<BiometricsStatus>;
    /**
     * Triggers a biometric unlock flow for the given user.
     */
    unlock_biometrics(user_id: UserId): Promise<void>;
    /**
      * Triggers a biometrics UV check. Retruns true if the check succeeded.
      */
    authenticate_biometrics(): Promise<boolean>;
}
"#;

#[wasm_bindgen]
extern "C" {
    /// JavaScript implementation of user lock-management operations used by shared unlock.
    #[wasm_bindgen(js_name = BiometricsUnlock, typescript_type = "BiometricsUnlock")]
    pub type RawJsBiometricsDriver;

    /// Returns the status of biometrics unlock for the given user.
    #[wasm_bindgen(method, catch)]
    async fn get_biometrics_status(
        this: &RawJsBiometricsDriver,
        user_id: UserId,
    ) -> Result<JsValue, JsValue>;

    /// Triggers a biometric unlock flow for the given user.
    #[wasm_bindgen(method, catch)]
    async fn unlock_biometrics(
        this: &RawJsBiometricsDriver,
        user_id: UserId,
    ) -> Result<(), JsValue>;

    /// Triggers a biometrics UV check. Retruns true if the check succeeded.
    #[wasm_bindgen(method, catch)]
    async fn authenticate_biometrics(this: &RawJsBiometricsDriver) -> Result<bool, JsValue>;
}

pub(super) struct JsBiometricsUnlock {
    runner: ThreadBoundRunner<RawJsBiometricsDriver>,
}

impl JsBiometricsUnlock {
    pub(super) fn new(runner: ThreadBoundRunner<RawJsBiometricsDriver>) -> Self {
        Self { runner }
    }

    pub(super) async fn get_biometrics_status(&self, user_id: UserId) -> BiometricsStatus {
        self.runner
            .run_in_thread(move |driver| async move {
                let status = driver
                    .get_biometrics_status(user_id)
                    .await
                    .unwrap_or(BiometricsStatus::NotEnabled.into());
                status.try_into().unwrap_or(BiometricsStatus::NotEnabled)
            })
            .await
            .unwrap_or(BiometricsStatus::NotEnabled)
    }

    pub(super) async fn unlock_biometrics(&self, user_id: UserId) {
        self.runner
            .run_in_thread(move |driver| async move {
                driver.unlock_biometrics(user_id).await.unwrap_or(())
            })
            .await
            .unwrap_or(())
    }

    pub(super) async fn authenticate_biometrics(&self) -> bool {
        self.runner
            .run_in_thread(move |driver| async move {
                driver.authenticate_biometrics().await.unwrap_or(false)
            })
            .await
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
/// The current biometric capability state for a specific user on this client.
pub enum BiometricsStatus {
    /// Biometrics is available and can be used immediately.
    Available,
    /// Biometrics is supported, but user interaction is required before unlock can proceed.
    UnlockNeeded,
    /// Biometrics hardware or platform support is unavailable.
    HardwareUnavailable,
    /// Biometrics is supported but not enabled for this user.
    NotEnabled,
}

impl TryFrom<JsValue> for BiometricsStatus {
    type Error = ();

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        let status = value.as_f64().ok_or(())? as u8;
        match status {
            0 => Ok(BiometricsStatus::Available),
            1 => Ok(BiometricsStatus::UnlockNeeded),
            2 => Ok(BiometricsStatus::HardwareUnavailable),
            3 => Ok(BiometricsStatus::NotEnabled),
            _ => Err(()),
        }
    }
}

/// RPC request to check whether biometric unlock is available for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetBiometricsStatusRequest {
    /// The user to check biometrics status for.
    pub user_id: UserId,
}

impl RpcRequest for GetBiometricsStatusRequest {
    type Response = BiometricsStatus;

    const NAME: &str = "GetBiometricsStatus";
}

/// RPC request to trigger biometric unlock for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockBiometricsRequest {
    /// The user to unlock with biometrics.
    pub user_id: UserId,
}

impl RpcRequest for UnlockBiometricsRequest {
    type Response = ();

    const NAME: &str = "UnlockBiometrics";
}

/// RPC request to trigger a biometrics UV check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticateBiometricsRequest;

impl RpcRequest for AuthenticateBiometricsRequest {
    type Response = bool;

    const NAME: &str = "AuthenticateBiometrics";
}

/// RPC handler for [`GetBiometricsStatusRequest`].
pub struct GetBiometricsStatusHandler {
    biometrics_unlock: JsBiometricsUnlock,
}

impl GetBiometricsStatusHandler {
    /// Creates a new handler backed by the provided biometrics driver.
    fn new(biometrics_unlock: JsBiometricsUnlock) -> Self {
        Self { biometrics_unlock }
    }
}

impl RpcHandler for GetBiometricsStatusHandler {
    type Request = GetBiometricsStatusRequest;

    async fn handle(&self, request: Self::Request) -> BiometricsStatus {
        self.biometrics_unlock
            .get_biometrics_status(request.user_id)
            .await
    }
}

/// RPC handler for [`UnlockBiometricsRequest`].
pub struct UnlockBiometricsHandler {
    biometrics_unlock: JsBiometricsUnlock,
}

impl UnlockBiometricsHandler {
    /// Creates a new handler backed by the provided biometrics driver.
    fn new(biometrics_unlock: JsBiometricsUnlock) -> Self {
        Self { biometrics_unlock }
    }
}

impl RpcHandler for UnlockBiometricsHandler {
    type Request = UnlockBiometricsRequest;

    async fn handle(&self, request: Self::Request) {
        self.biometrics_unlock
            .unlock_biometrics(request.user_id)
            .await
    }
}

/// RPC handler for [`AuthenticateBiometricsRequest`].
pub struct AuthenticateBiometricsHandler {
    biometrics_unlock: JsBiometricsUnlock,
}

impl AuthenticateBiometricsHandler {
    /// Creates a new handler backed by the provided biometrics driver.
    fn new(biometrics_unlock: JsBiometricsUnlock) -> Self {
        Self { biometrics_unlock }
    }
}

impl RpcHandler for AuthenticateBiometricsHandler {
    type Request = AuthenticateBiometricsRequest;

    async fn handle(&self, _: Self::Request) -> bool {
        self.biometrics_unlock.authenticate_biometrics().await
    }
}

/// Registers shared-unlock biometrics RPC handlers on the IPC client.
#[wasm_bindgen(js_name = ipcRegisterBiometricsHandlers)]
pub async fn ipc_register_biometrics_handlers(
    ipc_client: &bitwarden_ipc::wasm::JsIpcClient,
    biometrics_unlock: RawJsBiometricsDriver,
) {
    let runner = ThreadBoundRunner::new(biometrics_unlock);
    let handler_driver = JsBiometricsUnlock::new(runner.clone());

    ipc_client
        .client
        .register_rpc_handler(GetBiometricsStatusHandler::new(handler_driver))
        .await;
    ipc_client
        .client
        .register_rpc_handler(UnlockBiometricsHandler::new(JsBiometricsUnlock::new(
            runner.clone(),
        )))
        .await;
    ipc_client
        .client
        .register_rpc_handler(AuthenticateBiometricsHandler::new(JsBiometricsUnlock::new(
            runner,
        )))
        .await;
}

/// Sends a `GetBiometricsStatus` RPC request to a destination endpoint.
#[wasm_bindgen(js_name = ipcRequestGetBiometricsStatus)]
pub async fn ipc_request_get_biometrics_status(
    ipc_client: &bitwarden_ipc::wasm::JsIpcClient,
    user_id: UserId,
    abort_signal: Option<AbortSignal>,
) -> Result<BiometricsStatus, RequestError> {
    ipc_client
        .client
        .request(
            GetBiometricsStatusRequest { user_id },
            Endpoint::DesktopRenderer,
            abort_signal.map(|signal| signal.to_cancellation_token()),
        )
        .await
}

/// Sends an `UnlockBiometrics` RPC request to a destination endpoint.
#[wasm_bindgen(js_name = ipcRequestUnlockBiometrics)]
pub async fn ipc_request_unlock_biometrics(
    ipc_client: &bitwarden_ipc::wasm::JsIpcClient,
    user_id: UserId,
    abort_signal: Option<AbortSignal>,
) -> Result<(), RequestError> {
    ipc_client
        .client
        .request(
            UnlockBiometricsRequest { user_id },
            Endpoint::DesktopRenderer,
            abort_signal.map(|signal| signal.to_cancellation_token()),
        )
        .await
}

/// Sends an `AuthenticateBiometrics` RPC request to a destination endpoint.
#[wasm_bindgen(js_name = ipcRequestAuthenticateBiometrics)]
pub async fn ipc_request_authenticate_biometrics(
    ipc_client: &bitwarden_ipc::wasm::JsIpcClient,
    abort_signal: Option<AbortSignal>,
) -> Result<bool, RequestError> {
    ipc_client
        .client
        .request(
            AuthenticateBiometricsRequest,
            Endpoint::DesktopRenderer,
            abort_signal.map(|signal| signal.to_cancellation_token()),
        )
        .await
}
