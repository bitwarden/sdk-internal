use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    discover::{DiscoverHandler, DiscoverRequest, DiscoverResponse},
    endpoint::Endpoint,
};

use super::{error::JsRequestError, JsIpcClient};

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
    timeout_ms: Option<u64>,
) -> Result<DiscoverResponse, JsRequestError> {
    let timeout = timeout_ms.map(|ms| std::time::Duration::from_millis(ms));
    Ok(ipc_client
        .client
        .request(DiscoverRequest, destination, timeout)
        .await?)
}
