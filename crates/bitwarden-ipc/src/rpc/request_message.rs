use serde::{Deserialize, Serialize};

use super::request::RpcRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequestMessage<Request: RpcRequest> {
    pub request: Request,
    pub request_id: String,
    pub request_type: String,
}

impl<Request> TryFrom<Vec<u8>> for RpcRequestMessage<Request>
where
    Request: RpcRequest + for<'de> Deserialize<'de>,
{
    type Error = serde_json::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        serde_json::from_slice(&value)
    }
}

impl<Request> TryFrom<RpcRequestMessage<Request>> for Vec<u8>
where
    Request: RpcRequest + Serialize,
{
    type Error = serde_json::Error;

    fn try_from(value: RpcRequestMessage<Request>) -> Result<Self, Self::Error> {
        serde_json::to_vec(&value)
    }
}
