use serde::{Deserialize, Serialize};

use crate::rpc::payload::RpcPayload;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResponse;

impl RpcPayload for PingRequest {
    type Response = PingResponse;
    type Error = ();

    fn name() -> String {
        "PingRequest".to_string()
    }
}
