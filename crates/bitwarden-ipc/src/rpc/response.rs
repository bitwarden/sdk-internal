use serde::{Deserialize, Serialize};

use super::payload::RpcPayload;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponseMessage<Payload: RpcPayload> {
    pub response: Payload::Response,
    pub request_id: String,
    pub request_type: String,
}

impl<Payload> TryFrom<Vec<u8>> for RpcResponseMessage<Payload>
where
    Payload: RpcPayload + for<'de> Deserialize<'de>,
    <Payload as RpcPayload>::Response: for<'de> Deserialize<'de>,
{
    type Error = serde_json::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        serde_json::from_slice(&value)
    }
}

impl<Payload> TryFrom<RpcResponseMessage<Payload>> for Vec<u8>
where
    Payload: RpcPayload + Serialize,
    <Payload as RpcPayload>::Response: Serialize,
{
    type Error = serde_json::Error;

    fn try_from(value: RpcResponseMessage<Payload>) -> Result<Self, Self::Error> {
        serde_json::to_vec(&value)
    }
}
