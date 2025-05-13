use std::convert::Infallible;

use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use {tsify_next::Tsify, wasm_bindgen::prelude::*};

use crate::{endpoint::Endpoint, rpc::request::RpcRequest, RpcHandler};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoverRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct DiscoverResponse {
    pub identity: Endpoint,
    pub version: String,
    pub sdk_version: String,
}

impl RpcRequest for DiscoverRequest {
    type Response = DiscoverResponse;

    fn name() -> String {
        "DiscoverRequest".to_string()
    }
}

impl TryFrom<DiscoverRequest> for Vec<u8> {
    type Error = Infallible;

    fn try_from(_value: DiscoverRequest) -> Result<Self, Self::Error> {
        Ok(vec![])
    }
}

impl TryFrom<Vec<u8>> for DiscoverRequest {
    type Error = Infallible;

    fn try_from(_value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(DiscoverRequest)
    }
}

impl TryFrom<DiscoverResponse> for Vec<u8> {
    type Error = serde_json::Error;

    fn try_from(value: DiscoverResponse) -> Result<Self, Self::Error> {
        serde_json::to_vec(&value)
    }
}

impl TryFrom<Vec<u8>> for DiscoverResponse {
    type Error = serde_json::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        serde_json::from_slice(&value)
    }
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
