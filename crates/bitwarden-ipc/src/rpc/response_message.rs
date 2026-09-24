use erased_serde::Serialize as ErasedSerialize;
use serde::{Deserialize, Serialize};

use super::error::RpcError;

/// Prefix for the per-request dedicated response topic, formatted as
/// `"{RPC_RESPONSE_PAYLOAD_TYPE_NAME}:{request_id}"`. Each response is published on the dedicated
/// topic carried by its request, so response types do not implement
/// [`PayloadTypeName`](crate::message::PayloadTypeName).
pub const RPC_RESPONSE_PAYLOAD_TYPE_NAME: &str = "RpcResponseMessage";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingRpcResponseMessage<T> {
    pub result: Result<T, RpcError>,
    pub request_id: String,
    pub request_type: String,
}

#[derive(Serialize)]
pub struct OutgoingRpcResponseMessage<'a> {
    pub result: Result<Box<dyn ErasedSerialize>, RpcError>,
    pub request_id: &'a str,
    pub request_type: &'a str,
}
