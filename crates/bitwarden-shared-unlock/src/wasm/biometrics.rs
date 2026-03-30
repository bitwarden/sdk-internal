use bitwarden_core::UserId;
use bitwarden_ipc::{Endpoint, IpcClientExt, RequestError, RpcHandler, RpcRequest};
use bitwarden_threading::{
	ThreadBoundRunner,
	cancellation_token::wasm::{AbortSignal, AbortSignalExt},
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

use super::drivers::{JsBiometricsUnlock, RawJsBiometricsUnlock};

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
	type Response = bool;

	const NAME: &str = "UnlockBiometrics";
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

	async fn handle(&self, request: Self::Request) -> bool {
		self.biometrics_unlock
			.unlock_biometrics(request.user_id)
			.await
	}
}

/// Registers shared-unlock biometrics RPC handlers on the IPC client.
#[wasm_bindgen(js_name = ipcRegisterBiometricsHandlers)]
pub async fn ipc_register_biometrics_handlers(
	ipc_client: &bitwarden_ipc::wasm::JsIpcClient,
	biometrics_unlock: RawJsBiometricsUnlock,
) {
	let runner = ThreadBoundRunner::new(biometrics_unlock);
	let handler_driver = JsBiometricsUnlock::new(runner.clone());

	ipc_client
		.client
		.register_rpc_handler(GetBiometricsStatusHandler::new(handler_driver))
		.await;
	ipc_client
		.client
		.register_rpc_handler(UnlockBiometricsHandler::new(JsBiometricsUnlock::new(runner)))
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
) -> Result<bool, RequestError> {
	ipc_client
		.client
		.request(
			UnlockBiometricsRequest { user_id },
			Endpoint::DesktopRenderer,
			abort_signal.map(|signal| signal.to_cancellation_token()),
		)
		.await
}
