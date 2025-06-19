use serde::{Deserialize, Serialize};

use super::error::RpcError;
use crate::{message::PayloadTypeName, serde_utils};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponseMessage {
    pub result: Result<Vec<u8>, RpcError>,
    pub request_id: String,
    pub request_type: String,
}

impl PayloadTypeName for RpcResponseMessage {
    const PAYLOAD_TYPE_NAME: &str = "RpcResponseMessage";
}

impl RpcResponseMessage {
    pub(crate) fn serialize(&self) -> Result<Vec<u8>, RpcError> {
        serde_utils::to_vec(self).map_err(|e| RpcError::ResponseSerializationError(e.to_string()))
    }

    pub(crate) fn deserialize(data: Vec<u8>) -> Result<Self, RpcError> {
        serde_utils::from_slice(&data)
            .map_err(|e| RpcError::ResponseDeserializationError(e.to_string()))
    }
}
