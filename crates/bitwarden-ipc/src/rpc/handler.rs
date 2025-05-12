use std::future::Future;

use serde::Deserialize;

use serde::Serialize;

use super::error::RpcError;
use super::request::RpcRequest;

pub trait RpcHandler {
    type Request: RpcRequest;

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

impl<T> RpcHandlerExt for T
where
    T: RpcHandler,
    T::Request: RpcRequest + Serialize + for<'de> Deserialize<'de>,
    <T::Request as RpcRequest>::Response: Serialize + for<'de> Deserialize<'de>,
{
    type Request = T::Request;

    fn serialize_request(&self, request: Self::Request) -> Result<Vec<u8>, RpcError> {
        serde_json::to_vec(&request).map_err(|e| RpcError::RequestSerializationError(e.to_string()))
    }

    fn deserialize_request(&self, request: Vec<u8>) -> Result<Self::Request, RpcError> {
        serde_json::from_slice(&request)
            .map_err(|e| RpcError::RequestDeserializationError(e.to_string()))
    }

    fn serialize_response(
        &self,
        request: <Self::Request as RpcRequest>::Response,
    ) -> Result<Vec<u8>, RpcError> {
        serde_json::to_vec(&request)
            .map_err(|e| RpcError::ResponseSerializationError(e.to_string()))
    }

    fn deserialize_response(
        &self,
        request: Vec<u8>,
    ) -> Result<<Self::Request as RpcRequest>::Response, RpcError> {
        serde_json::from_slice(&request)
            .map_err(|e| RpcError::ResponseDeserializationError(e.to_string()))
    }
}

#[async_trait::async_trait]
pub(crate) trait ErasedRpcHandler: Send + Sync {
    async fn handle(&self, serialized_request: Vec<u8>) -> Result<Vec<u8>, RpcError>;
}

#[async_trait::async_trait]
impl<T> ErasedRpcHandler for T
where
    T: RpcHandler + Send + Sync,
    T::Request: RpcRequest + Serialize + for<'de> Deserialize<'de>,
    <T::Request as RpcRequest>::Response: Serialize + for<'de> Deserialize<'de>,
{
    async fn handle(&self, serialized_request: Vec<u8>) -> Result<Vec<u8>, RpcError> {
        let request: T::Request = self.deserialize_request(serialized_request)?;

        let response = self.handle(request).await;

        self.serialize_response(response)
    }
}
