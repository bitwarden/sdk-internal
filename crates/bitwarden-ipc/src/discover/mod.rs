use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use {tsify::Tsify, wasm_bindgen::prelude::*};

use crate::{RpcHandler, rpc::request::RpcRequest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoverRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct DiscoverResponse {
    pub version: String,
}

impl RpcRequest for DiscoverRequest {
    type Response = DiscoverResponse;

    const NAME: &str = "DiscoverRequest";
}

pub struct DiscoverHandler {
    response: DiscoverResponse,
}

impl DiscoverHandler {
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
