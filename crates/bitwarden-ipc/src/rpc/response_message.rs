use erased_serde::Serialize as ErasedSerialize;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::error::RpcError;
use crate::{message::PayloadTypeName, serde_utils};

/// Payload type name shared by every RPC response, also used as the topic responses are published
/// on.
pub const RPC_RESPONSE_PAYLOAD_TYPE_NAME: &str = "RpcResponseMessage";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingRpcResponseMessage<T> {
    pub result: Result<T, RpcError>,
    pub request_id: String,
    pub request_type: String,
}

/// Represents the payload of an RPC response, mirroring [`RpcRequestPayload`] on the response side.
///
/// Every response shares a single topic, so a subscription receives responses for other in-flight
/// requests too. This type lets the requester read the correlation metadata (`request_id`) from the
/// envelope *without* first deserializing the body into the expected response type. Only once the
/// `request_id` confirms the message belongs to this request is the body deserialized, so a typing
/// failure is a genuine error for this request rather than an unrelated concurrent response.
///
/// [`RpcRequestPayload`]: crate::rpc::request_message::RpcRequestPayload
pub struct RpcResponsePayload {
    data: Vec<u8>,
    partial: PartialRpcResponseMessage,
}

impl RpcResponsePayload {
    pub fn from_slice(data: Vec<u8>) -> Result<Self, serde_utils::DeserializeError> {
        let partial: PartialRpcResponseMessage = serde_utils::from_slice(&data)?;

        Ok(Self { data, partial })
    }

    pub fn request_id(&self) -> &str {
        &self.partial.request_id
    }

    /// Deserialize the full response, including the body, into the concrete response type. Call
    /// this only after [`Self::request_id`] confirms the response belongs to this request.
    pub fn deserialize_full<T>(&self) -> Result<IncomingRpcResponseMessage<T>, RpcError>
    where
        T: DeserializeOwned,
    {
        serde_utils::from_slice(&self.data)
            .map_err(|e| RpcError::ResponseDeserialization(e.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PartialRpcResponseMessage {
    pub request_id: String,
}

#[derive(Serialize)]
pub struct OutgoingRpcResponseMessage<'a> {
    pub result: Result<Box<dyn ErasedSerialize>, RpcError>,
    pub request_id: &'a str,
    pub request_type: &'a str,
}

impl<T> PayloadTypeName for IncomingRpcResponseMessage<T> {
    const PAYLOAD_TYPE_NAME: &str = RPC_RESPONSE_PAYLOAD_TYPE_NAME;
}

impl<'a> PayloadTypeName for OutgoingRpcResponseMessage<'a> {
    const PAYLOAD_TYPE_NAME: &'static str = RPC_RESPONSE_PAYLOAD_TYPE_NAME;
}
