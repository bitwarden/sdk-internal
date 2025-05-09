use std::future::Future;

use serde::Deserialize;

use serde::Serialize;

use super::error::RpcError;

pub trait RpcPayload: Serialize + for<'de> Deserialize<'de> {
    /// The type of the response.
    type Response: Serialize + for<'de> Deserialize<'de>;

    /// The type of the error.
    type Error: Serialize + for<'de> Deserialize<'de>;

    fn name() -> String;
}

pub trait RpcHandler {
    type Payload: RpcPayload;

    fn handle(
        &self,
        payload: Self::Payload,
    ) -> impl Future<Output = <Self::Payload as RpcPayload>::Response> + Send;
}

pub(crate) trait RpcHandlerExt {
    type Payload: RpcPayload;

    fn serialize_request(&self, payload: Self::Payload) -> Result<Vec<u8>, RpcError> {
        serde_json::to_vec(&payload).map_err(|e| RpcError::RequestSerializationError(e.to_string()))
    }

    fn deserialize_request(&self, payload: Vec<u8>) -> Result<Self::Payload, RpcError> {
        serde_json::from_slice(&payload)
            .map_err(|e| RpcError::RequestDeserializationError(e.to_string()))
    }

    fn serialize_response(
        &self,
        payload: <Self::Payload as RpcPayload>::Response,
    ) -> Result<Vec<u8>, RpcError> {
        serde_json::to_vec(&payload)
            .map_err(|e| RpcError::ResponseSerializationError(e.to_string()))
    }

    fn deserialize_response(
        &self,
        payload: Vec<u8>,
    ) -> Result<<Self::Payload as RpcPayload>::Response, RpcError> {
        serde_json::from_slice(&payload)
            .map_err(|e| RpcError::ResponseDeserializationError(e.to_string()))
    }

    // fn erased_types(self) -> Box<dyn ErasedRpcHandler>
    // where
    //     Self: Sized + 'static,
    // {
    //     Box::new(self)
    // }
}

impl<T> RpcHandlerExt for T
where
    T: RpcHandler,
{
    type Payload = T::Payload;
}

#[async_trait::async_trait]
pub(crate) trait ErasedRpcHandler {
    async fn handle(&self, serialized_payload: Vec<u8>) -> Result<Vec<u8>, RpcError>;
}

#[async_trait::async_trait]
impl<T> ErasedRpcHandler for T
where
    T: RpcHandler + Send + Sync,
    T::Payload: 'static,
    <T::Payload as RpcPayload>::Response: 'static,
    <T::Payload as RpcPayload>::Error: 'static,
{
    async fn handle(&self, serialized_payload: Vec<u8>) -> Result<Vec<u8>, RpcError> {
        let payload: T::Payload = self.deserialize_request(serialized_payload)?;

        let response = self.handle(payload).await;

        self.serialize_response(response)
    }
}
