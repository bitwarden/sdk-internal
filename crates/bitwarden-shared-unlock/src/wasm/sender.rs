use std::sync::Arc;

use bitwarden_ipc::{Endpoint, OutgoingMessage};
use wasm_bindgen_futures::spawn_local;

use crate::{Message, MessageSender};

fn clone_ipc_client(
    ipc_client: &bitwarden_ipc::wasm::JsIpcClient,
) -> bitwarden_ipc::wasm::JsIpcClient {
    bitwarden_ipc::wasm::JsIpcClient {
        client: Arc::clone(&ipc_client.client),
    }
}

pub(super) struct WasmSender {
    ipc_client: bitwarden_ipc::wasm::JsIpcClient,
}

impl WasmSender {
    pub(super) fn new(ipc_client: &bitwarden_ipc::wasm::JsIpcClient) -> Self {
        Self {
            ipc_client: clone_ipc_client(ipc_client),
        }
    }
}

impl Clone for WasmSender {
    fn clone(&self) -> Self {
        Self {
            ipc_client: clone_ipc_client(&self.ipc_client),
        }
    }
}

impl MessageSender for WasmSender {
    fn send_message(&self, message: Message, recipient: Endpoint) {
        let payload = match message.to_cbor() {
            Ok(payload) => payload,
            Err(error) => {
                tracing::error!(?error, "Failed to serialize shared unlock IPC message");
                return;
            }
        };

        let outgoing_message = OutgoingMessage {
            payload,
            destination: recipient,
            topic: Some("password-manager.shared-unlock".to_string()),
        };

        let ipc_client = clone_ipc_client(&self.ipc_client);

        spawn_local(async move {
            if let Err(error) = ipc_client.send(outgoing_message).await {
                tracing::error!(?error, "Failed to send shared unlock IPC message");
            }
        });
    }
}
