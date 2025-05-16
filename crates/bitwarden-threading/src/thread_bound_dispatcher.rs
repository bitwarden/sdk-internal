#![allow(dead_code)]
#![allow(unused_variables)]

use std::{future::Future, pin::Pin, sync::Arc};

use thiserror::Error;
#[cfg(not(target_arch = "wasm32"))]
use tokio::task::spawn_local;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::spawn_local;

struct CallRequest<ThreadState> {
    function: Box<dyn FnOnce(Arc<ThreadState>) -> Pin<Box<dyn Future<Output = ()>>> + Send>,
}

#[derive(Debug, Error)]
pub enum CallError {
    #[error("Failed to request function call: {0}")]
    ChannelSend(String),

    #[error("Failed to receive return value: {0}")]
    ChannelReceive(String),
}

pub struct ThreadBoundDispatcher<ThreadState> {
    call_channel_tx: tokio::sync::mpsc::Sender<CallRequest<ThreadState>>,
}

impl<ThreadState> ThreadBoundDispatcher<ThreadState>
where
    ThreadState: 'static,
{
    pub fn new(state: ThreadState) -> Self {
        let (call_channel_tx, mut call_channel_rx) =
            tokio::sync::mpsc::channel::<CallRequest<ThreadState>>(1);

        spawn_local(async move {
            let state = Arc::new(state);
            while let Some(request) = call_channel_rx.recv().await {
                (request.function)(state.clone()).await;
            }
        });

        ThreadBoundDispatcher { call_channel_tx }
    }

    pub async fn call<F, Output>(&self, function: F) -> Result<Output, CallError>
    where
        F: FnOnce(Arc<ThreadState>) -> Pin<Box<dyn Future<Output = Output>>> + Send + 'static,
        Output: Send + Sync + 'static,
    {
        let (return_channel_tx, return_channel_rx) = tokio::sync::oneshot::channel();

        let function_wrapper: Box<
            dyn FnOnce(Arc<ThreadState>) -> Pin<Box<dyn Future<Output = ()>>> + Send,
        > = Box::new(|state| {
            let result = function(state);
            Box::pin(async move {
                return_channel_tx.send(result.await).unwrap_or_else(|_| {
                    log::warn!("ThreadBoundDispatcher failed to send result back to the caller");
                });
            })
        });
        self.call_channel_tx
            .send(CallRequest {
                function: function_wrapper,
            })
            .await
            .map_err(|e| CallError::ChannelSend(e.to_string()))?;

        return_channel_rx
            .await
            .map_err(|e| CallError::ChannelReceive(e.to_string()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Utility function to run a test in a local context (allows using tokio::..::spawn_local)
    async fn run_test<F>(test: F) -> F::Output
    where
        F: std::future::Future,
    {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let local_set = tokio::task::LocalSet::new();
            local_set.run_until(test).await
        }

        #[cfg(target_arch = "wasm32")]
        {
            test.await
        }
    }

    async fn run_in_another_thread<F>(test: F)
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send,
    {
        #[cfg(not(target_arch = "wasm32"))]
        {
            tokio::spawn(test).await.expect("Thread panicked");
        }

        #[cfg(target_arch = "wasm32")]
        {
            test.await;
        }
    }

    #[tokio::test]
    async fn calls_function_and_returns_value() {
        #[derive(Default)]
        struct Target {
            /// This is a marker to ensure that the struct is not Send
            _un_send_marker: std::marker::PhantomData<*const ()>,
        }

        impl Target {
            pub fn add(&self, input: (i32, i32)) -> i32 {
                input.0 + input.1
            }
        }

        run_test(async {
            let target = Target::default();

            let dispatcher = ThreadBoundDispatcher::new(target);

            let result = dispatcher
                .call(|target| {
                    let input = (1, 2);
                    let result = target.add(input);
                    Box::pin(async move { result })
                })
                .await
                .expect("Calling function failed");

            assert_eq!(result, 3);
        })
        .await;
    }

    #[tokio::test]
    async fn calls_async_function_and_returns_value() {
        #[derive(Default)]
        struct Target {
            /// This is a marker to ensure that the struct is not Send
            _un_send_marker: std::marker::PhantomData<*const ()>,
        }

        impl Target {
            pub async fn add(&self, input: (i32, i32)) -> i32 {
                input.0 + input.1
            }
        }

        run_test(async {
            let target = Target::default();

            let dispatcher = ThreadBoundDispatcher::new(target);

            let result = dispatcher
                .call(|target| {
                    Box::pin(async move {
                        let input = (1, 2);
                        let result = target.add(input).await;
                        result
                    })
                })
                .await
                .expect("Calling function failed");

            assert_eq!(result, 3);
        })
        .await;
    }
}
