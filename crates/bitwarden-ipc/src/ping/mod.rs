use serde::{Deserialize, Serialize};

use crate::rpc::request::RpcRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResponse;

impl RpcRequest for PingRequest {
    type Response = PingResponse;

    fn name() -> String {
        "PingRequest".to_string()
    }
}
