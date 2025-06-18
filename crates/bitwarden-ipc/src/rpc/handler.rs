use std::future::Future;

use super::{error::RpcError, request::RpcRequest};
use crate::serde_utils;

/// Trait defining a handler for RPC requests.
/// These can registered with the IPC client and will be used to handle incoming RPC requests.
pub trait RpcHandler {
    /// The request type that this handler can process.
    type Request: RpcRequest;

    /// Handle the request. Any errors that occur should be defined as part of the `RpcRequest`
    /// type.
    fn handle(
        &self,
        request: Self::Request,
    ) -> impl Future<Output = <Self::Request as RpcRequest>::Response> + Send;
}

pub(crate) trait RpcHandlerExt {
    type Request: RpcRequest;

    fn serialize_request(&self, request: Self::Request) -> Result<Vec<u8>, RpcError>;

    fn deserialize_request(&self, request: Vec<u8>) -> Result<Self::Request, RpcError>;

    fn serialize_response(
        &self,
        request: <Self::Request as RpcRequest>::Response,
    ) -> Result<Vec<u8>, RpcError>;

    fn deserialize_response(
        &self,
        request: Vec<u8>,
    ) -> Result<<Self::Request as RpcRequest>::Response, RpcError>;
}

impl<T: RpcHandler> RpcHandlerExt for T
where
    T: RpcHandler,
{
    type Request = T::Request;

    fn serialize_request(&self, request: Self::Request) -> Result<Vec<u8>, RpcError> {
        serde_utils::to_vec(&request)
            .map_err(|e| RpcError::RequestSerializationError(e.to_string()))
    }

    fn deserialize_request(&self, request: Vec<u8>) -> Result<Self::Request, RpcError> {
        serde_utils::from_slice(&request)
            .map_err(|e| RpcError::RequestDeserializationError(e.to_string()))
    }

    fn serialize_response(
        &self,
        request: <Self::Request as RpcRequest>::Response,
    ) -> Result<Vec<u8>, RpcError> {
        serde_utils::to_vec(&request)
            .map_err(|e| RpcError::ResponseSerializationError(e.to_string()))
    }

    fn deserialize_response(
        &self,
        request: Vec<u8>,
    ) -> Result<<Self::Request as RpcRequest>::Response, RpcError> {
        serde_utils::from_slice(&request)
            .map_err(|e| RpcError::ResponseDeserializationError(e.to_string()))
    }
}

#[async_trait::async_trait]
pub(crate) trait ErasedRpcHandler: Send + Sync {
    async fn handle(&self, serialized_request: Vec<u8>) -> Result<Vec<u8>, RpcError>;
}

#[async_trait::async_trait]
impl<H> ErasedRpcHandler for H
where
    H: RpcHandler + Send + Sync,
{
    async fn handle(&self, serialized_request: Vec<u8>) -> Result<Vec<u8>, RpcError> {
        let request: H::Request = self.deserialize_request(serialized_request)?;

        let response = self.handle(request).await;

        self.serialize_response(response)
    }
}
