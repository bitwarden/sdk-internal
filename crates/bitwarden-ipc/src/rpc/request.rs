use serde::{Deserialize, Serialize};

use super::payload::RpcPayload;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequestMessage<Payload: RpcPayload> {
    pub request: Payload,
    pub request_id: String,
    pub request_type: String,
}

impl<Payload> TryFrom<Vec<u8>> for RpcRequestMessage<Payload>
where
    Payload: RpcPayload + for<'de> Deserialize<'de>,
{
    type Error = serde_json::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        serde_json::from_slice(&value)
    }
}

impl<Payload> TryFrom<RpcRequestMessage<Payload>> for Vec<u8>
where
    Payload: RpcPayload + Serialize,
{
    type Error = serde_json::Error;

    fn try_from(value: RpcRequestMessage<Payload>) -> Result<Self, Self::Error> {
        serde_json::to_vec(&value)
    }
}
