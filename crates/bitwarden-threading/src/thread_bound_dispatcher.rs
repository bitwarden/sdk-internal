#![allow(dead_code)]
#![allow(unused_variables)]

use std::{future::Future, pin::Pin};

use thiserror::Error;
#[cfg(not(target_arch = "wasm32"))]
use tokio::task::spawn_local;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::spawn_local;

struct CallRequest<ThreadState> {
    // function: fn(&ThreadState) -> Box<dyn Future<Output = Output> + Send>,
    // function: fn(&ThreadState) -> Box<dyn Future<Output = ()> + Send>,
    // function: Box<dyn FnOnce(&ThreadState) -> Box<dyn Future<Output = ()> + Send> + Send>,
    function: Box<dyn FnOnce(&ThreadState) -> Pin<Box<dyn Future<Output = ()> + Send>>>,
    // return_channel: tokio::sync::oneshot::Sender<Output>,
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
            while let Some(request) = call_channel_rx.recv().await {
                (request.function)(&state).await;
            }
        });

        ThreadBoundDispatcher { call_channel_tx }
    }

    pub async fn call<Output>(
        &self,
        function: fn(&ThreadState) -> Pin<Box<dyn Future<Output = Output> + Send + Sync>>,
    ) -> Result<Output, CallError>
    where
        Output: Send + Sync + 'static,
    {
        let (return_channel_tx, return_channel_rx) = tokio::sync::oneshot::channel();

        let any_function: Box<
            dyn FnOnce(&ThreadState) -> Pin<Box<dyn Future<Output = ()> + Send>>,
        > = Box::new(move |state| {
            let result = function(state);

            Box::pin(async move {
                // // Call the function with the state
                let result = result.await;
                return_channel_tx.send(result).unwrap_or_else(|_| {
                    log::warn!("ThreadBoundDispatcher failed to send result back to the caller");
                });
            })
        });
        self.call_channel_tx
            .send(CallRequest {
                function: any_function,
                // return_channel: return_channel_tx,
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
            // let target = Arc::new(RwLock::new(Target::default()));
            let target = Target::default();

            let dispatcher = ThreadBoundDispatcher::new(target);
            // let add_bridge = bridge_function(move |input| {
            //     let target = target.clone();
            //     async move { target.read().await.add(input) }
            // });

            let result = dispatcher
                .call(|target| {
                    let input = (1, 2);
                    let result = target.add(input);
                    Box::pin(async move { result })
                })
                .await
                .expect("Calling function failed");

            // assert_eq!(result, 3);
        })
        .await;
    }

    // #[tokio::test]
    // async fn calls_bridged_object_and_returns_value() {
    //     #[derive(Default)]
    //     struct Target {
    //         /// This is a marker to ensure that the struct is not Send
    //         _un_send_marker: std::marker::PhantomData<*const ()>,
    //     }

    //     impl Target {
    //         pub fn add(&self, input: (i32, i32)) -> i32 {
    //             input.0 + input.1
    //         }
    //     }

    //     impl CallTarget for Target {
    //         type Input = (i32, i32);
    //         type Output = i32;

    //         async fn call(&self, input: Self::Input) -> Self::Output {
    //             self.add(input)
    //         }
    //     }

    //     run_test(async {
    //         let target = Target::default();
    //         let add_bridge = bridge(target);

    //         let result = add_bridge
    //             .call((1, 2))
    //             .await
    //             .expect("Calling function failed");

    //         assert_eq!(result, 3);
    //     })
    //     .await;
    // }

    // #[tokio::test]
    // async fn calls_and_modifies_object_using_bridging_functions() {
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

    // // #[tokio::test]
    // // async fn calls_and_modifies_object_using_command_enum() {
    // //     #[derive(Default)]
    // //     struct Target {
    // //         /// This is a marker to ensure that the struct is not Send
    // //         _un_send_marker: std::marker::PhantomData<*const ()>,

    // //         value: i32,
    // //     }

    // //     impl Target {
    // //         pub fn get_value(&self) -> i32 {
    // //             self.value
    // //         }

    // //         pub fn set_value(&mut self, value: i32) {
    // //             self.value = value;
    // //         }
    // //     }

    // //     enum Command {
    // //         GetValue { input: (), output: i32 },
    // //         SetValue { input: i32, output: () },
    // //     }

    // //     impl CallTarget for Target {
    // //         type Input = Command;
    // //         type Output = i32;

    // // TODO: Tricky, I'd like to keep the Output more specific
    // //         async fn call(&self, input: Self::Input) -> Self::Output {
    // //             match input {
    // //                 Command::GetValue => self.get_value(),
    // //                 Command::SetValue(value) => {
    // //                     self.set_value(value);
    // //                     0
    // //                 }
    // //             }
    // //         }
    // //     }

    // //     run_test(async {
    // //         let parent_target = Arc::new(RwLock::new(Target::default()));

    // //         let target = parent_target.clone();
    // //         let set_value_bridge = bridge_function(move |input| {
    // //             let target = target.clone();
    // //             async move { target.write().await.set_value(input) }
    // //         });

    // //         let target = parent_target.clone();
    // //         let get_value_bridge = bridge_function(move |_: ()| {
    // //             let target = target.clone();
    // //             async move { target.read().await.get_value() }
    // //         });

    // //         // Call the set_value_bridge with a value
    // //         set_value_bridge
    // //             .call(42)
    // //             .await
    // //             .expect("Calling get function failed");
    // //         let result = get_value_bridge
    // //             .call(())
    // //             .await
    // //             .expect("Calling set function failed");

    // //         // Call the get_value_bridge to check if the value was set correctly
    // //         assert_eq!(result, 42);
    // //     })
    // //     .await;
    // // }

    // #[tokio::test]
    // async fn calling_works_across_threads() {
    //     #[derive(Default)]
    //     struct Target {
    //         /// This is a marker to ensure that the struct is not Send
    //         _un_send_marker: std::marker::PhantomData<*const ()>,
    //     }

    //     impl Target {
    //         pub fn add(&self, input: (i32, i32)) -> i32 {
    //             input.0 + input.1
    //         }
    //     }

    //     impl CallTarget for Target {
    //         type Input = (i32, i32);
    //         type Output = i32;

    //         async fn call(&self, input: Self::Input) -> Self::Output {
    //             self.add(input)
    //         }
    //     }

    //     run_test(async {
    //         let target = Target::default();
    //         let add_bridge = bridge(target);

    //         // Spawn a new thread to call the function
    //         run_in_another_thread(async move {
    //             let result = add_bridge
    //                 .call((1, 2))
    //                 .await
    //                 .expect("Calling function failed");

    //             assert_eq!(result, 3);
    //         })
    //         .await;
    //     })
    //     .await;
    // }
}
