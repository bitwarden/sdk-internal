#![allow(dead_code)]
#![allow(unused_variables)]

use std::{future::Future, pin::Pin, rc::Rc};

use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(not(target_arch = "wasm32"))]
use tokio::task::spawn_local;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::spawn_local;

type CallFunction<ThreadState> =
    Box<dyn FnOnce(Rc<ThreadState>) -> Pin<Box<dyn Future<Output = ()>>> + Send>;

struct CallRequest<ThreadState> {
    function: CallFunction<ThreadState>,
}

/// The call failed before it could return a value. This should not happen unless
/// the thread panics, which can only happen if the function passed to `run_in_thread`
/// panics.
#[derive(Debug, Error)]
#[error("The call failed before it could return a value: {0}")]
#[bitwarden_error(basic)]
pub struct CallError(String);

/// A runner that takes a non-`Send`, non-`Sync` state and makes it `Send + Sync` compatible.
///
/// `ThreadBoundRunner` is designed to safely encapsulate a `!Send + !Sync` state object by
/// pinning it to a single thread using `spawn_local`. It provides a `Send + Sync` API that
/// allows other threads to submit tasks (function pointers or closures) that operate on the
/// thread-bound state.
///
/// Tasks are queued via an internal channel and are executed sequentially on the owning thread.
///
/// # Example
/// ```ignore
/// let runner = ThreadBoundRunner::new(my_state);
///
/// runner.run_in_thread(|state| async move {
///     // do something with `state`
/// });
/// ```
///
/// This pattern is useful for interacting with APIs or data structures that must remain
/// on the same thread, such as GUI toolkits, WebAssembly contexts, or other thread-bound
/// environments.
#[derive(Clone)]
pub struct ThreadBoundRunner<ThreadState> {
    call_channel_tx: tokio::sync::mpsc::Sender<CallRequest<ThreadState>>,
}

impl<ThreadState> ThreadBoundRunner<ThreadState>
where
    ThreadState: 'static,
{
    #[allow(missing_docs)]
    pub fn new(state: ThreadState) -> Self {
        let (call_channel_tx, mut call_channel_rx) =
            tokio::sync::mpsc::channel::<CallRequest<ThreadState>>(1);

        spawn_local(async move {
            let state = Rc::new(state);
            while let Some(request) = call_channel_rx.recv().await {
                spawn_local((request.function)(state.clone()));
            }
        });

        ThreadBoundRunner { call_channel_tx }
    }

    /// Submit a task to be executed on the thread-bound state.
    ///
    /// The provided function is executed on the thread that owns the internal `ThreadState`,
    /// ensuring safe access to `!Send + !Sync` data. Tasks are dispatched in the order they are
    /// received, but because they are asynchronous, multiple tasks may be in-flight and running
    /// concurrently if their futures yield.
    ///
    /// # Returns
    /// A future that resolves to the result of the function once it has been executed.
    pub async fn run_in_thread<F, Fut, Output>(&self, function: F) -> Result<Output, CallError>
    where
        F: FnOnce(Rc<ThreadState>) -> Fut + Send + 'static,
        Fut: Future<Output = Output>,
        Output: Send + Sync + 'static,
    {
        let (return_channel_tx, return_channel_rx) = tokio::sync::oneshot::channel();
        let request = CallRequest {
            function: Box::new(|state| {
                Box::pin(async move {
                    let result = function(state);
                    return_channel_tx.send(result.await).unwrap_or_else(|_| {
                        log::warn!(
                            "ThreadBoundDispatcher failed to send result back to the caller"
                        );
                    });
                })
            }),
        };

        self.call_channel_tx
            .send(request)
            .await
            .expect("Call channel should not be able to close while anything still still has a reference to this object");
        return_channel_rx
            .await
            .map_err(|e| CallError(e.to_string()))
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

    #[derive(Default)]
    struct State {
        /// This is a marker to ensure that the struct is not Send
        _un_send_marker: std::marker::PhantomData<*const ()>,
    }

    impl State {
        pub fn add(&self, input: (i32, i32)) -> i32 {
            input.0 + input.1
        }

        #[allow(clippy::unused_async)]
        pub async fn async_add(&self, input: (i32, i32)) -> i32 {
            input.0 + input.1
        }
    }

    #[tokio::test]
    async fn calls_function_and_returns_value() {
        run_test(async {
            let runner = ThreadBoundRunner::new(State::default());

            let result = runner
                .run_in_thread(|state| async move {
                    let input = (1, 2);
                    state.add(input)
                })
                .await
                .expect("Calling function failed");

            assert_eq!(result, 3);
        })
        .await;
    }

    #[tokio::test]
    async fn calls_async_function_and_returns_value() {
        run_test(async {
            let runner = ThreadBoundRunner::new(State::default());

            let result = runner
                .run_in_thread(|state| async move {
                    let input = (1, 2);
                    state.async_add(input).await
                })
                .await
                .expect("Calling function failed");

            assert_eq!(result, 3);
        })
        .await;
    }

    #[tokio::test]
    async fn can_continue_running_if_a_call_panics() {
        run_test(async {
            let runner = ThreadBoundRunner::new(State::default());

            runner
                .run_in_thread::<_, _, ()>(|state| async move {
                    panic!("This is a test panic");
                })
                .await
                .expect_err("Calling function should have panicked");

            let result = runner
                .run_in_thread(|state| async move {
                    let input = (1, 2);
                    state.async_add(input).await
                })
                .await
                .expect("Calling function failed");

            assert_eq!(result, 3);
        })
        .await;
    }
}
