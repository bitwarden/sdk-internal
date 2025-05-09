use serde::{Deserialize, Serialize};

use super::payload::RpcRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponseMessage<Request: RpcRequest> {
    pub response: Request::Response,
    pub request_id: String,
    pub request_type: String,
}

impl<Request> TryFrom<Vec<u8>> for RpcResponseMessage<Request>
where
    Request: RpcRequest + for<'de> Deserialize<'de>,
    <Request as RpcRequest>::Response: for<'de> Deserialize<'de>,
{
    type Error = serde_json::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        serde_json::from_slice(&value)
    }
}

impl<Request> TryFrom<RpcResponseMessage<Request>> for Vec<u8>
where
    Request: RpcRequest + Serialize,
    <Request as RpcRequest>::Response: Serialize,
{
    type Error = serde_json::Error;

    fn try_from(value: RpcResponseMessage<Request>) -> Result<Self, Self::Error> {
        serde_json::to_vec(&value)
    }
}
