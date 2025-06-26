use erased_serde::Serialize as ErasedSerialize;
use tokio::sync::RwLock;

use super::handler::{ErasedRpcHandler, RpcHandler};
use crate::rpc::{error::RpcError, request::RpcRequest, request_message::RpcRequestPayload};

pub struct RpcHandlerRegistry {
    handlers: RwLock<std::collections::HashMap<String, Box<dyn ErasedRpcHandler>>>,
}

impl RpcHandlerRegistry {
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(std::collections::HashMap::new()),
        }
    }

    pub async fn register<H>(&self, handler: H)
    where
        H: RpcHandler + ErasedRpcHandler + 'static,
    {
        let name = H::Request::NAME.to_owned();
        self.handlers.write().await.insert(name, Box::new(handler));
    }

    pub async fn handle(
        &self,
        request: &RpcRequestPayload,
    ) -> Result<Box<dyn ErasedSerialize>, RpcError> {
        match self.handlers.read().await.get(request.request_type()) {
            Some(handler) => handler.handle(request).await,
            None => Err(RpcError::NoHandlerFound),
        }
    }
}

#[cfg(test)]
mod test {
    use serde::{de::DeserializeOwned, Deserialize, Serialize};

    use super::*;
    use crate::{
        rpc::{request::RpcRequest, request_message::RpcRequestMessage},
        serde_utils,
    };

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TestRequest {
        a: i32,
        b: i32,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TestResponse {
        result: i32,
    }

    impl RpcRequest for TestRequest {
        type Response = TestResponse;

        const NAME: &str = "TestRequest";
    }

    struct TestHandler;

    impl RpcHandler for TestHandler {
        type Request = TestRequest;

        async fn handle(&self, request: Self::Request) -> TestResponse {
            TestResponse {
                result: request.a + request.b,
            }
        }
    }

    #[tokio::test]
    async fn handle_returns_error_when_no_handler_can_be_found() {
        let registry = RpcHandlerRegistry::new();

        let request = TestRequest { a: 1, b: 2 };
        let message = RpcRequestMessage {
            request,
            request_id: "test_id".to_string(),
            request_type: "TestRequest".to_string(),
        };
        let serialized_request =
            RpcRequestPayload::from_slice(serde_utils::to_vec(&message).unwrap()).unwrap();

        let result = registry.handle(&serialized_request).await;

        assert!(matches!(result, Err(RpcError::NoHandlerFound)));
    }

    #[tokio::test]
    async fn handle_runs_previously_registered_handler() {
        let registry = RpcHandlerRegistry::new();

        registry.register(TestHandler).await;

        let request = TestRequest { a: 1, b: 2 };
        let message = RpcRequestMessage {
            request,
            request_id: "test_id".to_string(),
            request_type: "TestRequest".to_string(),
        };
        let serialized_request =
            RpcRequestPayload::from_slice(serde_utils::to_vec(&message).unwrap()).unwrap();

        let result = registry
            .handle(&serialized_request)
            .await
            .expect("Failed to handle request");
        let response: TestResponse = deserialize_erased_object(&result);

        assert_eq!(response.result, 3);
    }

    fn deserialize_erased_object<T, R>(value: &T) -> R
    where
        T: Serialize,
        R: DeserializeOwned,
    {
        let serialized = serde_utils::to_vec(value).expect("Failed to serialize erased serialize");

        serde_utils::from_slice(&serialized).expect("Failed to deserialize erased serialize")
    }
}
