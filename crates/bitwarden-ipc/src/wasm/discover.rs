use wasm_bindgen::prelude::wasm_bindgen;

use super::{error::JsRequestError, JsIpcClient};
use crate::{
    discover::{DiscoverHandler, DiscoverRequest, DiscoverResponse},
    endpoint::Endpoint,
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
/// Note: Timeout is not yet supported because tokio::time does not support WASM
pub async fn ipc_request_discover(
    ipc_client: &JsIpcClient,
    destination: Endpoint,
) -> Result<DiscoverResponse, JsRequestError> {
    Ok(ipc_client
        .client
        .request(DiscoverRequest, destination, None)
        .await?)
}
