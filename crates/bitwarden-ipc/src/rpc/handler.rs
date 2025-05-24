use std::future::Future;

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
    T::Request: RpcRequest + TryFrom<Vec<u8>> + TryInto<Vec<u8>>,
    <T::Request as RpcRequest>::Response: TryFrom<Vec<u8>> + TryInto<Vec<u8>>,
    <T::Request as TryFrom<Vec<u8>>>::Error: std::fmt::Display,
    <T::Request as TryInto<Vec<u8>>>::Error: std::fmt::Display,
    <<T::Request as RpcRequest>::Response as TryFrom<Vec<u8>>>::Error: std::fmt::Display,
    <<T::Request as RpcRequest>::Response as TryInto<Vec<u8>>>::Error: std::fmt::Display,
{
    type Request = T::Request;

    fn serialize_request(&self, request: Self::Request) -> Result<Vec<u8>, RpcError> {
        request
            .try_into()
            .map_err(|e| RpcError::RequestSerializationError(e.to_string()))
    }

    fn deserialize_request(&self, request: Vec<u8>) -> Result<Self::Request, RpcError> {
        request
            .try_into()
            .map_err(|e: <T::Request as TryFrom<Vec<u8>>>::Error| {
                RpcError::RequestDeserializationError(e.to_string())
            })
    }

    fn serialize_response(
        &self,
        request: <Self::Request as RpcRequest>::Response,
    ) -> Result<Vec<u8>, RpcError> {
        request
            .try_into()
            .map_err(|e| RpcError::ResponseSerializationError(e.to_string()))
    }

    fn deserialize_response(
        &self,
        request: Vec<u8>,
    ) -> Result<<Self::Request as RpcRequest>::Response, RpcError> {
        request.try_into().map_err(
            |e: <<T::Request as RpcRequest>::Response as TryFrom<Vec<u8>>>::Error| {
                RpcError::ResponseDeserializationError(e.to_string())
            },
        )
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
    H::Request: RpcRequest + TryFrom<Vec<u8>> + TryInto<Vec<u8>>,
    <H::Request as RpcRequest>::Response: TryFrom<Vec<u8>> + TryInto<Vec<u8>>,
    <H::Request as TryFrom<Vec<u8>>>::Error: std::fmt::Display,
    <H::Request as TryInto<Vec<u8>>>::Error: std::fmt::Display,
    <<H::Request as RpcRequest>::Response as TryFrom<Vec<u8>>>::Error: std::fmt::Display,
    <<H::Request as RpcRequest>::Response as TryInto<Vec<u8>>>::Error: std::fmt::Display,
{
    async fn handle(&self, serialized_request: Vec<u8>) -> Result<Vec<u8>, RpcError> {
        let request: H::Request = self.deserialize_request(serialized_request)?;

        let response = self.handle(request).await;

        self.serialize_response(response)
    }
}
