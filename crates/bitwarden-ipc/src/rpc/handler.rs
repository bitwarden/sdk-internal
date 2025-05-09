use std::future::Future;

use serde::Deserialize;

use serde::Serialize;

use super::error::RpcError;
use super::payload::RpcRequest;

pub trait RpcHandler {
    type Request: RpcRequest;

    fn handle(
        &self,
        payload: Self::Request,
    ) -> impl Future<Output = <Self::Request as RpcRequest>::Response> + Send;
}

pub(crate) trait RpcHandlerExt {
    type Request: RpcRequest;

    fn serialize_request(&self, payload: Self::Request) -> Result<Vec<u8>, RpcError>;

    fn deserialize_request(&self, payload: Vec<u8>) -> Result<Self::Request, RpcError>;

    fn serialize_response(
        &self,
        payload: <Self::Request as RpcRequest>::Response,
    ) -> Result<Vec<u8>, RpcError>;

    fn deserialize_response(
        &self,
        payload: Vec<u8>,
    ) -> Result<<Self::Request as RpcRequest>::Response, RpcError>;
}

impl<T> RpcHandlerExt for T
where
    T: RpcHandler,
    T::Request: RpcRequest + Serialize + for<'de> Deserialize<'de>,
    <T::Request as RpcRequest>::Response: Serialize + for<'de> Deserialize<'de>,
{
    type Request = T::Request;

    fn serialize_request(&self, payload: Self::Request) -> Result<Vec<u8>, RpcError> {
        serde_json::to_vec(&payload).map_err(|e| RpcError::RequestSerializationError(e.to_string()))
    }

    fn deserialize_request(&self, payload: Vec<u8>) -> Result<Self::Request, RpcError> {
        serde_json::from_slice(&payload)
            .map_err(|e| RpcError::RequestDeserializationError(e.to_string()))
    }

    fn serialize_response(
        &self,
        payload: <Self::Request as RpcRequest>::Response,
    ) -> Result<Vec<u8>, RpcError> {
        serde_json::to_vec(&payload)
            .map_err(|e| RpcError::ResponseSerializationError(e.to_string()))
    }

    fn deserialize_response(
        &self,
        payload: Vec<u8>,
    ) -> Result<<Self::Request as RpcRequest>::Response, RpcError> {
        serde_json::from_slice(&payload)
            .map_err(|e| RpcError::ResponseDeserializationError(e.to_string()))
    }
}

#[async_trait::async_trait]
pub(crate) trait ErasedRpcHandler {
    async fn handle(&self, serialized_payload: Vec<u8>) -> Result<Vec<u8>, RpcError>;
}

#[async_trait::async_trait]
impl<T> ErasedRpcHandler for T
where
    T: RpcHandler + Send + Sync,
    T::Request: RpcRequest + Serialize + for<'de> Deserialize<'de>,
    <T::Request as RpcRequest>::Response: Serialize + for<'de> Deserialize<'de>,
{
    async fn handle(&self, serialized_payload: Vec<u8>) -> Result<Vec<u8>, RpcError> {
        let payload: T::Request = self.deserialize_request(serialized_payload)?;

        let response = self.handle(payload).await;

        self.serialize_response(response)
    }
}
