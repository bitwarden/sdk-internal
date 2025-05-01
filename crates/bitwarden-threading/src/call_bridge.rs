use thiserror::Error;
#[cfg(not(feature = "wasm"))]
use tokio::task::spawn_local;

#[cfg(feature = "wasm")]
use wasm_bindgen_futures::spawn_local;

use crate::call_target::CallTarget;

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

pub struct CallBridge<Input, Output> {
    call_channel_tx: tokio::sync::mpsc::Sender<CallRequest<Input, Output>>,
}

impl<Input, OutputValue> CallBridge<Input, OutputValue> {
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

pub fn bridge<Target>(call_target: Target) -> CallBridge<Target::Input, Target::Output>
where
    Target: CallTarget + 'static,
{
    let (call_channel_tx, mut call_channel_rx) =
        tokio::sync::mpsc::channel::<CallRequest<Target::Input, Target::Output>>(1);

    spawn_local(async move {
        while let Some(request) = call_channel_rx.recv().await {
            let output = call_target.call(request.input).await;
            let _ = request.return_channel.send(output); // Ignore any potential errors
        }
    });

    CallBridge { call_channel_tx }
}

pub fn bridge_function<F, Input, OutputFuture>(
    call_target: F,
) -> CallBridge<Input, OutputFuture::Output>
where
    F: Fn(Input) -> OutputFuture + 'static,
    Input: Send + 'static,
    OutputFuture: std::future::Future + 'static,
    OutputFuture::Output: Send + 'static,
{
    struct FunctionWrapper<F, I, O> {
        _marker: std::marker::PhantomData<(I, O)>,
        function: F,
    }
    impl<F, Input, OutputFuture> CallTarget for FunctionWrapper<F, Input, OutputFuture>
    where
        F: Fn(Input) -> OutputFuture + 'static,
        Input: Send + 'static,
        OutputFuture: std::future::Future,
        OutputFuture::Output: Send + 'static,
    {
        type Input = Input;
        type Output = OutputFuture::Output;

        fn call(&self, input: Self::Input) -> impl std::future::Future<Output = Self::Output> {
            (self.function)(input)
        }
    }

    bridge(FunctionWrapper {
        _marker: std::marker::PhantomData,
        function: call_target,
    })
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use tokio::sync::RwLock;

    use super::*;

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
    async fn calls_bridged_function_and_returns_value() {
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
            let target = Arc::new(RwLock::new(Target::default()));
            let add_bridge = bridge_function(move |input| {
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
    async fn calls_bridged_object_and_returns_value() {
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

        impl CallTarget for Target {
            type Input = (i32, i32);
            type Output = i32;

            async fn call(&self, input: Self::Input) -> Self::Output {
                self.add(input)
            }
        }

        run_test(async {
            let target = Target::default();
            let add_bridge = bridge(target);

            let result = add_bridge
                .call((1, 2))
                .await
                .expect("Calling function failed");

            assert_eq!(result, 3);
        })
        .await;
    }

    #[tokio::test]
    async fn calls_and_modifies_object_using_bridging_functions() {
        #[derive(Default)]
        struct Target {
            /// This is a marker to ensure that the struct is not Send
            _un_send_marker: std::marker::PhantomData<*const ()>,

            value: i32,
        }

        impl Target {
            pub fn get_value(&self) -> i32 {
                self.value
            }

            pub fn set_value(&mut self, value: i32) {
                self.value = value;
            }
        }

        run_test(async {
            let parent_target = Arc::new(RwLock::new(Target::default()));

            let target = parent_target.clone();
            let set_value_bridge = bridge_function(move |input| {
                let target = target.clone();
                async move { target.write().await.set_value(input) }
            });

            let target = parent_target.clone();
            let get_value_bridge = bridge_function(move |_: ()| {
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

    // #[tokio::test]
    // async fn calls_and_modifies_object_using_command_enum() {
    //     #[derive(Default)]
    //     struct Target {
    //         /// This is a marker to ensure that the struct is not Send
    //         _un_send_marker: std::marker::PhantomData<*const ()>,

    //         value: i32,
    //     }

    //     impl Target {
    //         pub fn get_value(&self) -> i32 {
    //             self.value
    //         }

    //         pub fn set_value(&mut self, value: i32) {
    //             self.value = value;
    //         }
    //     }

    //     enum Command {
    //         GetValue { input: (), output: i32 },
    //         SetValue { input: i32, output: () },
    //     }

    //     impl CallTarget for Target {
    //         type Input = Command;
    //         type Output = i32;

    // TODO: Tricky, I'd like to keep the Output more specific
    //         async fn call(&self, input: Self::Input) -> Self::Output {
    //             match input {
    //                 Command::GetValue => self.get_value(),
    //                 Command::SetValue(value) => {
    //                     self.set_value(value);
    //                     0
    //                 }
    //             }
    //         }
    //     }

    //     run_test(async {
    //         let parent_target = Arc::new(RwLock::new(Target::default()));

    //         let target = parent_target.clone();
    //         let set_value_bridge = bridge_function(move |input| {
    //             let target = target.clone();
    //             async move { target.write().await.set_value(input) }
    //         });

    //         let target = parent_target.clone();
    //         let get_value_bridge = bridge_function(move |_: ()| {
    //             let target = target.clone();
    //             async move { target.read().await.get_value() }
    //         });

    //         // Call the set_value_bridge with a value
    //         set_value_bridge
    //             .call(42)
    //             .await
    //             .expect("Calling get function failed");
    //         let result = get_value_bridge
    //             .call(())
    //             .await
    //             .expect("Calling set function failed");

    //         // Call the get_value_bridge to check if the value was set correctly
    //         assert_eq!(result, 42);
    //     })
    //     .await;
    // }

    #[tokio::test]
    async fn calling_works_across_threads() {
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

        impl CallTarget for Target {
            type Input = (i32, i32);
            type Output = i32;

            async fn call(&self, input: Self::Input) -> Self::Output {
                self.add(input)
            }
        }

        run_test(async {
            let target = Target::default();
            let add_bridge = bridge(target);

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
