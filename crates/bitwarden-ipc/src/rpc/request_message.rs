use serde::{Deserialize, Serialize};

use crate::{message::PayloadTypeName, rpc::error::RpcError, serde_utils};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequestMessage {
    pub request: Vec<u8>,
    pub request_id: String,
    pub request_type: String,
}

impl PayloadTypeName for RpcRequestMessage {
    fn name() -> String {
        "RpcRequestMessage".to_string()
    }
}

impl RpcRequestMessage {
    pub(crate) fn serialize(&self) -> Result<Vec<u8>, RpcError> {
        serde_utils::to_vec(self).map_err(|e| RpcError::RequestSerializationError(e.to_string()))
    }

    pub(crate) fn deserialize(data: Vec<u8>) -> Result<Self, RpcError> {
        serde_utils::from_slice(&data)
            .map_err(|e| RpcError::RequestDeserializationError(e.to_string()))
    }
}
