//! A built-in RPC request/response pair for autotype over the SDK's encrypted IPC.
//!
//! This is the seam that lets the autotype feature start using [`bitwarden_ipc`] rather than the
//! desktop client's unencrypted Electron IPC channels. It is deliberately an echo — the responding
//! client returns the message it was given, unchanged — so it proves the channel round-trips real
//! data without committing to a wire format for autotype itself. Real autotype requests get
//! layered on later following the same shape.
//!
//! Modeled on `bitwarden_ipc`'s `discover` module, which serves the same purpose for liveness
//! checks.
//!
//! # Responding to echo requests
//!
//! Register the handler so the client answers incoming echo requests:
//!
//! ```rust,no_run
//! # use bitwarden_autotype::echo::AutotypeEchoHandler;
//! # use bitwarden_ipc::{IpcClient, IpcClientExt};
//! # async fn example(ipc_client: impl IpcClient) {
//! ipc_client.register_rpc_handler(AutotypeEchoHandler).await;
//! # }
//! ```
//!
//! # Sending an echo request
//!
//! ```rust,no_run
//! # use bitwarden_autotype::echo::AutotypeEchoRequest;
//! # use bitwarden_ipc::{Endpoint, IpcClient, IpcClientExt};
//! # async fn example(
//! #     ipc_client: impl IpcClient,
//! #     destination: Endpoint,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! let response = ipc_client
//!     .request(
//!         AutotypeEchoRequest {
//!             message: "ping".to_string(),
//!         },
//!         destination,
//!         None, // optional cancellation token
//!     )
//!     .await?;
//! assert_eq!(response.message, "ping");
//! # Ok(())
//! # }
//! ```

use bitwarden_ipc::{RpcHandler, RpcRequest};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use {tsify::Tsify, wasm_bindgen::prelude::*};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A request asking the receiving client to echo a message back.
pub struct AutotypeEchoRequest {
    /// The message to be echoed back by the responding client.
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
/// The response to an [`AutotypeEchoRequest`].
pub struct AutotypeEchoResponse {
    /// The message received in the request, returned unchanged.
    pub message: String,
}

impl RpcRequest for AutotypeEchoRequest {
    type Response = AutotypeEchoResponse;

    const NAME: &str = "AutotypeEchoRequest";
}

/// An [`RpcHandler`] that returns the request's message unchanged. Register it on an
/// `IpcClient` to make that client answer autotype echo requests.
pub struct AutotypeEchoHandler;

impl RpcHandler for AutotypeEchoHandler {
    type Request = AutotypeEchoRequest;

    async fn handle(&self, request: Self::Request) -> AutotypeEchoResponse {
        AutotypeEchoResponse {
            message: request.message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_handler_echoes_the_message_unchanged() {
        let response = AutotypeEchoHandler
            .handle(AutotypeEchoRequest {
                message: "ping".to_string(),
            })
            .await;

        assert_eq!(response.message, "ping");
    }

    #[tokio::test]
    async fn the_handler_echoes_an_empty_message() {
        let response = AutotypeEchoHandler
            .handle(AutotypeEchoRequest {
                message: String::new(),
            })
            .await;

        assert_eq!(response.message, "");
    }

    // The RPC layer serializes with serde_json (see bitwarden-ipc's `serde_utils`), so these
    // assert against the same encoding used on the wire.
    #[test]
    fn the_request_survives_a_serde_round_trip() {
        let serialized = serde_json::to_vec(&AutotypeEchoRequest {
            message: "ping".to_string(),
        })
        .expect("Serialization should not fail");

        let deserialized: AutotypeEchoRequest =
            serde_json::from_slice(&serialized).expect("Deserialization should not fail");

        assert_eq!(deserialized.message, "ping");
    }

    #[test]
    fn the_response_survives_a_serde_round_trip() {
        let serialized = serde_json::to_vec(&AutotypeEchoResponse {
            message: "pong".to_string(),
        })
        .expect("Serialization should not fail");

        let deserialized: AutotypeEchoResponse =
            serde_json::from_slice(&serialized).expect("Deserialization should not fail");

        assert_eq!(deserialized.message, "pong");
    }

    #[test]
    fn the_request_name_is_stable() {
        // Handlers are looked up by this name across IPC endpoints, so changing it breaks
        // compatibility with any client built against the old value.
        assert_eq!(AutotypeEchoRequest::NAME, "AutotypeEchoRequest");
    }
}
