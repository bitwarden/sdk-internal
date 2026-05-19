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
    let (tx, rx) = tokio::sync::oneshot::channel();
    wasm_bindgen_futures::spawn_local(async move {
        gloo_timers::future::sleep(duration).await;
        let _ = tx.send(());
    });

    tokio::pin!(future);
    tokio::select! {
        result = &mut future => Ok(result),
        _ = rx => Err(ElapsedError),
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
