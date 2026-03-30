use bitwarden_core::UserId;
use bitwarden_ipc::{Endpoint, IpcClientExt, RequestError, RpcHandler, RpcRequest};
use bitwarden_threading::{
	ThreadBoundRunner,
	cancellation_token::wasm::{AbortSignal, AbortSignalExt},
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::wasm_bindgen;

use super::drivers::{JsBiometricsUnlock, RawJsBiometricsUnlock};

/// RPC request to check whether biometric unlock is available for a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetBiometricAvailableRequest {
	/// The user to check biometric availability for.
	pub user_id: UserId,
}

impl RpcRequest for GetBiometricAvailableRequest {
	type Response = bool;

	const NAME: &str = "GetBiometricAvailable";
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

/// RPC handler for [`GetBiometricAvailableRequest`].
pub struct GetBiometricAvailableHandler {
	biometrics_unlock: JsBiometricsUnlock,
}

impl GetBiometricAvailableHandler {
	/// Creates a new handler backed by the provided biometrics driver.
	fn new(biometrics_unlock: JsBiometricsUnlock) -> Self {
		Self { biometrics_unlock }
	}
}

impl RpcHandler for GetBiometricAvailableHandler {
	type Request = GetBiometricAvailableRequest;

	async fn handle(&self, request: Self::Request) -> bool {
		self.biometrics_unlock
			.get_biometric_available(request.user_id)
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
		.register_rpc_handler(GetBiometricAvailableHandler::new(handler_driver))
		.await;
	ipc_client
		.client
		.register_rpc_handler(UnlockBiometricsHandler::new(JsBiometricsUnlock::new(runner)))
		.await;
}

/// Sends a `GetBiometricAvailable` RPC request to a destination endpoint.
#[wasm_bindgen(js_name = ipcRequestGetBiometricAvailable)]
pub async fn ipc_request_get_biometric_available(
	ipc_client: &bitwarden_ipc::wasm::JsIpcClient,
	user_id: UserId,
	abort_signal: Option<AbortSignal>,
) -> Result<bool, RequestError> {
	ipc_client
		.client
		.request(
			GetBiometricAvailableRequest { user_id },
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
