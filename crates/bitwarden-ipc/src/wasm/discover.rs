use bitwarden_threading::cancellation_token::wasm::{AbortSignal, AbortSignalExt};
use wasm_bindgen::prelude::wasm_bindgen;

use super::JsIpcClient;
use crate::{
    discover::{DiscoverHandler, DiscoverRequest, DiscoverResponse},
    endpoint::Endpoint,
    RequestError,
};

#[wasm_bindgen(js_name = ipcRegisterDiscoverHandler)]
/// Registers a DiscoverHandler so that the client can respond to DiscoverRequests.
pub async fn ipc_register_discover_handler(ipc_client: &JsIpcClient, response: DiscoverResponse) {
    ipc_client
        .client
        .register_rpc_handler(DiscoverHandler::new(response))
        .await;
}

#[wasm_bindgen(js_name = ipcRequestDiscover)]
/// Sends a DiscoverRequest to the specified destination and returns the response.
pub async fn ipc_request_discover(
    ipc_client: &JsIpcClient,
    destination: Endpoint,
    abort_signal: Option<AbortSignal>,
) -> Result<DiscoverResponse, RequestError> {
    ipc_client
        .client
        .request(
            DiscoverRequest,
            destination,
            abort_signal.map(|c| c.to_cancellation_token()),
        )
        .await
}
