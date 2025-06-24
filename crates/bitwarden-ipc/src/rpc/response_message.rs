use erased_serde::Serialize as ErasedSerialize;
use serde::{Deserialize, Serialize};

use super::error::RpcError;
use crate::message::PayloadTypeName;

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

impl<T> PayloadTypeName for IncomingRpcResponseMessage<T> {
    const PAYLOAD_TYPE_NAME: &str = "RpcResponseMessage";
}

impl<'a> PayloadTypeName for OutgoingRpcResponseMessage<'a> {
    const PAYLOAD_TYPE_NAME: &'static str = "RpcResponseMessage";
}
