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
}
