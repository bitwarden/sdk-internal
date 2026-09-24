use serde::{Deserialize, Serialize};

use crate::{
    rpc::{error::RpcError, request::RpcRequest, response_message::RPC_RESPONSE_PAYLOAD_TYPE_NAME},
    serde_utils,
};

/// Fixed topic every RPC request is published on. The receiver matches incoming messages against
/// this topic to route them to the handler registry.
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

    /// The topic the response is published on. The handler publishes its reply here, and the
    /// requester subscribes to it to receive the response.
    pub fn response_topic(&self) -> &str {
        &self.partial.response_topic
    }

    pub fn deserialize_full<T>(&self) -> Result<RpcRequestMessage<T>, RpcError>
    where
        T: RpcRequest,
    {
        serde_utils::from_slice(&self.data)
            .map_err(|e| RpcError::RequestDeserialization(e.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequestMessage<T> {
    pub request: T,
    pub request_id: String,
    pub request_type: String,
    /// Dedicated topic the response should be published on. See
    /// [`RpcRequestPayload::response_topic`].
    pub response_topic: String,
}

impl<T: RpcRequest> RpcRequestMessage<T> {
    /// Wrap a request, assigning it a fresh id and its own dedicated response topic.
    pub fn new(request: T) -> Self {
        let request_id = uuid::Uuid::new_v4().to_string();
        let response_topic = format!("{RPC_RESPONSE_PAYLOAD_TYPE_NAME}:{request_id}");
        Self {
            request,
            request_type: T::NAME.to_owned(),
            request_id,
            response_topic,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PartialRpcRequestMessage {
    pub request_id: String,
    pub request_type: String,
    pub response_topic: String,
}
