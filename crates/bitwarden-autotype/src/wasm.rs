//! WASM bindings for the autotype IPC requests, exposed to the clients through
//! `@bitwarden/sdk-internal`.

use bitwarden_ipc::{Endpoint, IpcClientExt, RequestError, wasm::JsIpcClient};
use bitwarden_threading::cancellation_token::wasm::{AbortSignal, AbortSignalExt};
use wasm_bindgen::prelude::wasm_bindgen;

use crate::echo::{AutotypeEchoHandler, AutotypeEchoRequest, AutotypeEchoResponse};

#[wasm_bindgen(js_name = autotypeRegisterEchoHandler)]
/// Registers an AutotypeEchoHandler so that the client can respond to AutotypeEchoRequests.
pub async fn autotype_register_echo_handler(ipc_client: &JsIpcClient) {
    ipc_client
        .client
        .register_rpc_handler(AutotypeEchoHandler)
        .await;
}

#[wasm_bindgen(js_name = autotypeRequestEcho)]
/// Sends an AutotypeEchoRequest to the specified destination and returns the response.
pub async fn autotype_request_echo(
    ipc_client: &JsIpcClient,
    destination: Endpoint,
    message: String,
    abort_signal: Option<AbortSignal>,
) -> Result<AutotypeEchoResponse, RequestError> {
    ipc_client
        .client
        .request(
            AutotypeEchoRequest { message },
            destination,
            abort_signal.map(|signal| signal.to_cancellation_token()),
        )
        .await
}
