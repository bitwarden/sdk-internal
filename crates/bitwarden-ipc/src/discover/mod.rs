#![doc = include_str!("README.md")]

use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use {tsify::Tsify, wasm_bindgen::prelude::*};

use crate::{RpcHandler, rpc::request::RpcRequest};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// A request to discover/ping a client.
pub struct DiscoverRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
/// The response to a discover/ping request.
pub struct DiscoverResponse {
    /// The version of the client that responded to the discover request.
    pub version: String,
}

impl RpcRequest for DiscoverRequest {
    type Response = DiscoverResponse;

    const NAME: &str = "DiscoverRequest";
}

/// A simple handler for the `DiscoverRequest` that always returns the same response.
/// Used to enable discovery/ping functionality and provide version information.
pub struct DiscoverHandler {
    response: DiscoverResponse,
}

impl DiscoverHandler {
    /// Creates a new `DiscoverHandler` with the given response.
    pub fn new(response: DiscoverResponse) -> Self {
        Self { response }
    }
}

impl RpcHandler for DiscoverHandler {
    type Request = DiscoverRequest;

    async fn handle(&self, _request: Self::Request) -> DiscoverResponse {
        self.response.clone()
    }
}
