use thiserror::Error;
#[cfg(not(feature = "wasm"))]
use tokio::task::spawn_local;

#[cfg(feature = "wasm")]
use wasm_bindgen_futures::spawn_local;

struct CallRequest<Input, OutputValue> {
    input: Input,
    return_channel: tokio::sync::oneshot::Sender<OutputValue>,
}

#[derive(Debug, Error)]
pub enum CallError {
    #[error("Failed to request function call: {0}")]
    ChannelSend(String),

    #[error("Failed to receive return value: {0}")]
    ChannelReceive(String),
}

pub struct FunctionBridge<Input, Output> {
    call_channel_tx: tokio::sync::mpsc::Sender<CallRequest<Input, Output>>,
}

impl<Input, OutputValue> FunctionBridge<Input, OutputValue> {
    pub async fn call(&self, input: Input) -> Result<OutputValue, CallError> {
        let (return_channel_tx, return_channel_rx) = tokio::sync::oneshot::channel();

        self.call_channel_tx
            .send(CallRequest {
                input,
                return_channel: return_channel_tx,
            })
            .await
            .map_err(|e| CallError::ChannelSend(e.to_string()))?;

        return_channel_rx
            .await
            .map_err(|e| CallError::ChannelReceive(e.to_string()))
    }
}

pub fn function_bridge<TargetFunction, Input, Output, OutputValue>(
    target_function: TargetFunction,
) -> FunctionBridge<Input, OutputValue>
where
    TargetFunction: Fn(Input) -> Output + 'static,
    Input: Send + 'static,
    Output: std::future::Future<Output = OutputValue>,
    OutputValue: Send + 'static,
{
    let (call_channel_tx, mut call_channel_rx) =
        tokio::sync::mpsc::channel::<CallRequest<Input, OutputValue>>(1);

    spawn_local(async move {
        while let Some(request) = call_channel_rx.recv().await {
            let output = target_function(request.input).await;
            let _ = request.return_channel.send(output); // Ignore any potential errors
        }
    });

    FunctionBridge { call_channel_tx }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use tokio::sync::RwLock;

    use super::*;

    #[derive(Default)]
    struct Target {
        /// This is a marker to ensure that the struct is not Send
        _un_send_marker: std::marker::PhantomData<*const ()>,

        value: i32,
    }

    impl Target {
        pub fn add(&self, input: (i32, i32)) -> i32 {
            input.0 + input.1
        }

        pub fn get_value(&self) -> i32 {
            self.value
        }

        pub fn set_value(&mut self, value: i32) {
            self.value = value;
        }
    }

    /// Utility function to run a test in a local context (allows using tokio::..::spawn_local)
    async fn run_test<F>(test: F) -> F::Output
    where
        F: std::future::Future,
    {
        #[cfg(not(feature = "wasm"))]
        {
            let local_set = tokio::task::LocalSet::new();
            local_set.run_until(test).await
        }

        #[cfg(feature = "wasm")]
        {
            test.await
        }
    }

    async fn run_in_another_thread<F>(test: F)
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send,
    {
        #[cfg(not(feature = "wasm"))]
        {
            tokio::spawn(test).await.expect("Thread panicked");
        }

        #[cfg(feature = "wasm")]
        {
            test.await;
        }
    }

    #[tokio::test]
    async fn calls_targeted_function_and_returns_value() {
        run_test(async {
            let target = Arc::new(RwLock::new(Target::default()));
            let add_bridge = function_bridge(move |input| {
                let target = target.clone();
                async move { target.read().await.add(input) }
            });

            let result = add_bridge
                .call((1, 2))
                .await
                .expect("Calling function failed");

            assert_eq!(result, 3);
        })
        .await;
    }

    #[tokio::test]
    async fn functions_can_modify_state() {
        run_test(async {
            let parent_target = Arc::new(RwLock::new(Target::default()));

            let target = parent_target.clone();
            let set_value_bridge = function_bridge(move |input| {
                let target = target.clone();
                async move { target.write().await.set_value(input) }
            });

            let target = parent_target.clone();
            let get_value_bridge = function_bridge(move |_: ()| {
                let target = target.clone();
                async move { target.read().await.get_value() }
            });

            // Call the set_value_bridge with a value
            set_value_bridge
                .call(42)
                .await
                .expect("Calling get function failed");
            let result = get_value_bridge
                .call(())
                .await
                .expect("Calling set function failed");

            // Call the get_value_bridge to check if the value was set correctly
            assert_eq!(result, 42);
        })
        .await;
    }

    #[tokio::test]
    async fn calling_works_across_threads() {
        run_test(async {
            let target = Arc::new(RwLock::new(Target::default()));
            let add_bridge = function_bridge(move |input| {
                let target = target.clone();
                async move { target.read().await.add(input) }
            });

            // Spawn a new thread to call the function
            run_in_another_thread(async move {
                let result = add_bridge
                    .call((1, 2))
                    .await
                    .expect("Calling function failed");

                assert_eq!(result, 3);
            })
            .await;
        })
        .await;
    }
}
