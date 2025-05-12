use tokio::sync::RwLock;

use crate::rpc::error::RpcError;

use super::handler::{ErasedRpcHandler, RpcHandler};
use super::request::RpcRequest;

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
        let name = H::Request::name();
        self.handlers.write().await.insert(name, Box::new(handler));
    }

    pub async fn handle(
        &self,
        name: &str,
        serialized_request: Vec<u8>,
    ) -> Result<Vec<u8>, RpcError> {
        match self.handlers.read().await.get(name) {
            Some(handler) => handler.handle(serialized_request).await,
            None => Err(RpcError::NoHandlerFound),
        }
    }
}

mod test {
    use serde::{Deserialize, Serialize};

    use crate::rpc::request::RpcRequest;

    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TestRequest {
        a: i32,
        b: i32,
    }

    impl RpcRequest for TestRequest {
        type Response = i32;

        fn name() -> String {
            "TestRequest".to_string()
        }
    }

    struct TestHandler;

    impl RpcHandler for TestHandler {
        type Request = TestRequest;

        async fn handle(&self, request: Self::Request) -> i32 {
            request.a + request.b
        }
    }

    #[tokio::test]
    async fn handle_returns_error_when_no_handler_can_be_found() {
        let registry = RpcHandlerRegistry::new();

        let request = TestRequest { a: 1, b: 2 };
        let request_bytes = serde_json::to_vec(&request).unwrap();

        let result = registry.handle("TestRequest", request_bytes).await;

        assert!(matches!(result, Err(RpcError::NoHandlerFound)));
    }

    #[tokio::test]
    async fn handle_runs_previously_registered_handler() {
        let registry = RpcHandlerRegistry::new();

        registry.register(TestHandler).await;

        let request = TestRequest { a: 1, b: 2 };
        let request_bytes = serde_json::to_vec(&request).unwrap();

        let result = registry
            .handle("TestRequest", request_bytes)
            .await
            .expect("Failed to handle request");
        let result: i32 = serde_json::from_slice(&result).expect("Failed to deserialize response");

        assert_eq!(result, 3);
    }
}
