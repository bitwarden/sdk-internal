use serde::{Deserialize, Serialize};

use super::error::RpcError;
use crate::message::PayloadTypeName;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponseMessage {
    pub result: Result<Vec<u8>, RpcError>,
    pub request_id: String,
    pub request_type: String,
}

impl PayloadTypeName for RpcResponseMessage {
    fn name() -> String {
        "RpcResponseMessage".to_string()
    }
}

impl TryFrom<Vec<u8>> for RpcResponseMessage {
    type Error = serde_json::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        serde_json::from_slice(&value)
    }
}

impl TryFrom<RpcResponseMessage> for Vec<u8> {
    type Error = serde_json::Error;

    fn try_from(value: RpcResponseMessage) -> Result<Self, Self::Error> {
        serde_json::to_vec(&value)
    }
}
