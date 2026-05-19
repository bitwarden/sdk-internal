use std::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
pub async fn sleep(duration: Duration) {
    tokio::time::sleep(duration).await;
}

#[cfg(target_arch = "wasm32")]
pub async fn sleep(duration: Duration) {
    use gloo_timers::future::sleep;

    sleep(duration).await;
}

/// Returned by [`timeout`] when the wrapped future did not complete in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElapsedError;

impl std::fmt::Display for ElapsedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("operation timed out")
    }
}

impl std::error::Error for ElapsedError {}

#[cfg(not(target_arch = "wasm32"))]
pub async fn timeout<F: std::future::Future>(
    duration: Duration,
    future: F,
) -> Result<F::Output, ElapsedError> {
    tokio::time::timeout(duration, future)
        .await
        .map_err(|_| ElapsedError)
}

#[cfg(target_arch = "wasm32")]
pub async fn timeout<F: std::future::Future>(
    duration: Duration,
    future: F,
) -> Result<F::Output, ElapsedError> {
    // Wrap the !Send `gloo_timers` future and the caller's future in a single
    // state machine that we then assert as `Send`. wasm32-unknown-unknown is
    // single-threaded, so the future is never actually moved across threads
    // and the trait bound on `CryptoProvider::send` is satisfied.
    wasm_send::WasmSend(async move {
        let sleep_fut = gloo_timers::future::sleep(duration);
        tokio::pin!(future);
        tokio::pin!(sleep_fut);
        tokio::select! {
            result = &mut future => Ok(result),
            _ = &mut sleep_fut => Err(Elapsed),
        }
    })
    .await
}

#[cfg(target_arch = "wasm32")]
mod wasm_send {
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll},
    };

    pub(super) struct WasmSend<F>(pub F);

    // SAFETY: wasm32-unknown-unknown is single-threaded; the value is never
    // actually sent across threads.
    unsafe impl<F> Send for WasmSend<F> {}
    // SAFETY: see above.
    unsafe impl<F> Sync for WasmSend<F> {}

    impl<F: Future> Future for WasmSend<F> {
        type Output = F::Output;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            // SAFETY: structural pin projection of the single inner field.
            unsafe { self.map_unchecked_mut(|s| &mut s.0) }.poll(cx)
        }
    }
}

#[cfg(test)]
mod test {
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    #[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
    async fn should_sleep_wasm() {
        use js_sys::Date;

        use super::*;

        console_error_panic_hook::set_once();
        let start = Date::now();

        sleep(Duration::from_millis(100)).await;

        let end = Date::now();
        let elapsed = end - start;

        assert!(elapsed >= 90.0, "Elapsed time was less than expected");
    }

    #[tokio::test]
    async fn should_sleep_tokio() {
        use std::time::Instant;

        use super::*;

        let start = Instant::now();

        sleep(Duration::from_millis(100)).await;

        let end = Instant::now();
        let elapsed = end.duration_since(start);

        assert!(
            elapsed >= Duration::from_millis(90),
            "Elapsed time was less than expected"
        );
    }

    #[tokio::test]
    async fn timeout_returns_value_when_future_completes_first() {
        use std::time::Duration;

        use super::timeout;

        let result = timeout(Duration::from_secs(5), async { 42 }).await;
        assert_eq!(result, Ok(42));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn timeout_returns_elapsed_when_sleep_first() {
        use std::time::Duration;

        use super::{ElapsedError, timeout};

        let result = timeout(
            Duration::from_millis(10),
            tokio::time::sleep(Duration::from_secs(60)),
        )
        .await;
        assert_eq!(result, Err(ElapsedError));
    }
}
