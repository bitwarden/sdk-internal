use std::sync::Arc;

use bitwarden_ipc::{Endpoint, OutgoingMessage};
use wasm_bindgen_futures::spawn_local;

use crate::{Message, MessageSender};

#[derive(Clone, Copy)]
pub(super) enum Role {
    Leader,
    Follower,
}

pub(super) struct WasmSender {
    ipc_client: Arc<bitwarden_ipc::IpcClient>,
    role: Role,
}

impl WasmSender {
    pub(super) fn new(ipc_client: &bitwarden_ipc::wasm::JsIpcClient, role: Role) -> Self {
        Self {
            ipc_client: ipc_client.client.clone(),
            role,
        }
    }
}

impl Clone for WasmSender {
    fn clone(&self) -> Self {
        Self {
            ipc_client: self.ipc_client.clone(),
            role: self.role,
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
            topic: match self.role {
                Role::Leader => {
                    Some("password-manager.shared-unlock.leader-to-follower".to_string())
                }
                Role::Follower => {
                    Some("password-manager.shared-unlock.follower-to-leader".to_string())
                }
            },
        };

        let ipc_client = self.ipc_client.clone();

        spawn_local(async move {
            if let Err(error) = ipc_client.send(outgoing_message).await {
                tracing::error!(?error, "Failed to send shared unlock IPC message");
            }
        });
    }
}
