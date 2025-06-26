use serde::{Deserialize, Serialize};

use crate::{
    message::PayloadTypeName,
    rpc::{error::RpcError, request::RpcRequest},
    serde_utils,
};

pub const RPC_REQUEST_PAYLOAD_TYPE_NAME: &str = "RpcRequestMessage";

/// Represents the payload of an RPC request.
/// It encapsulates both the serialized and deserialized form of the request. This
/// allows for efficient handling of requests without having to implement deserialization
/// in multiple places.
pub struct RpcRequestPayload {
    data: Vec<u8>,
    partial: PartialRpcRequestMessage,
}

impl RpcRequestPayload {
    pub fn from_slice(data: Vec<u8>) -> Result<Self, serde_utils::DeserializeError> {
        let partial: PartialRpcRequestMessage = serde_utils::from_slice(&data)?;

        Ok(Self { data, partial })
    }

    pub fn request_id(&self) -> &str {
        &self.partial.request_id
    }

    pub fn request_type(&self) -> &str {
        &self.partial.request_type
    }

    pub fn deserialize_full<T>(&self) -> Result<RpcRequestMessage<T>, RpcError>
    where
        T: RpcRequest,
    {
        serde_utils::from_slice(&self.data)
            .map_err(|e| RpcError::RequestDeserializationError(e.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequestMessage<T> {
    pub request: T,
    pub request_id: String,
    pub request_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PartialRpcRequestMessage {
    pub request_id: String,
    pub request_type: String,
}

impl<T> PayloadTypeName for RpcRequestMessage<T> {
    const PAYLOAD_TYPE_NAME: &str = RPC_REQUEST_PAYLOAD_TYPE_NAME;
}
