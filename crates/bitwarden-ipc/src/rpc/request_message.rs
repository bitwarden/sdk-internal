use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequestMessage {
    pub request: Vec<u8>,
    pub request_id: String,
    pub request_type: String,
}

impl TryFrom<Vec<u8>> for RpcRequestMessage {
    type Error = serde_json::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        serde_json::from_slice(&value)
    }
}

impl TryFrom<RpcRequestMessage> for Vec<u8> {
    type Error = serde_json::Error;

    fn try_from(value: RpcRequestMessage) -> Result<Self, Self::Error> {
        serde_json::to_vec(&value)
    }
}
