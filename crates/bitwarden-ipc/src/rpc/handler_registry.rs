use crate::rpc::error::RpcError;

use super::handler::{ErasedRpcHandler, RpcHandler, RpcPayload};

pub struct RpcHandlerRegistry {
    handlers: std::collections::HashMap<String, Box<dyn ErasedRpcHandler>>,
}

impl RpcHandlerRegistry {
    pub fn new() -> Self {
        Self {
            handlers: std::collections::HashMap::new(),
        }
    }

    pub fn register<H>(&mut self, handler: H)
    where
        H: RpcHandler + ErasedRpcHandler + 'static,
    {
        let name = H::Payload::name();
        self.handlers.insert(name, Box::new(handler));
    }

    pub async fn handle(&self, name: &str, payload: Vec<u8>) -> Result<Vec<u8>, Vec<u8>> {
        match self.handlers.get(name) {
            Some(handler) => {}
            None => {
                let error: RpcError<()> = RpcError::NoHandlerFound;
                return Err(error.serialize());
            }
        }

        todo!()
        // if let Some(handler) = self.handlers.get(name) {
        //     handler.handle(payload)
        // } else {
        //     Err(Box::new("Handler not found") as Box<dyn std::any::Any>)
        // }
    }

    // pub fn handle(
    //     &self,
    //     name: &str,
    //     payload: Vec<u8>,
    // ) -> Result<Box<dyn std::any::Any>, Box<dyn std::any::Any>> {
    //     if let Some(handler) = self.handlers.get(name) {
    //         handler.handle(payload)
    //     } else {
    //         Err(Box::new("Handler not found") as Box<dyn std::any::Any>)
    //     }
    // }
}

mod test {
    use serde::{Deserialize, Serialize};

    // use crate::rpc::error::RpcError;

    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TestPayload {
        a: i32,
        b: i32,
    }

    impl RpcPayload for TestPayload {
        type Response = i32;
        type Error = String;

        fn name() -> String {
            "TestPayload".to_string()
        }
    }

    struct TestHandler;

    impl RpcHandler for TestHandler {
        type Payload = TestPayload;

        async fn handle(&self, payload: Self::Payload) -> Result<i32, String> {
            Ok(payload.a + payload.b)
        }
    }

    #[tokio::test]
    async fn handle_returns_error_when_no_handler_can_be_found() {
        let registry = RpcHandlerRegistry::new();

        let payload = TestPayload { a: 1, b: 2 };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();

        let result = registry
            .handle("TestPayload", payload_bytes)
            .await
            .expect_err("Expected error when no handler is found");
        let error: RpcError<<TestPayload as RpcPayload>::Error> =
            serde_json::from_slice(&result).expect("Failed to deserialize error");

        assert!(matches!(error, RpcError::NoHandlerFound));
    }

    #[tokio::test]
    async fn handle_runs_previously_registered_handler() {
        let mut registry = RpcHandlerRegistry::new();

        registry.register(TestHandler);

        let payload = TestPayload { a: 1, b: 2 };
        let payload_bytes = serde_json::to_vec(&payload).unwrap();

        let result = registry
            .handle("TestPayload", payload_bytes)
            .await
            .expect("Failed to handle request");
        let result: i32 = serde_json::from_slice(&result).expect("Failed to deserialize response");

        assert_eq!(result, 3);
    }
}
