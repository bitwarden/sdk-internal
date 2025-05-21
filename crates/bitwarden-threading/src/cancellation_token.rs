pub use tokio_util::sync::CancellationToken;

#[cfg(target_arch = "wasm32")]
pub mod wasm {
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::spawn_local;

    use super::*;

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = console, js_name = log)]
        pub fn console_log(a: JsValue);

        #[wasm_bindgen]
        #[derive(Clone)]
        pub type AbortController;

        #[wasm_bindgen(constructor)]
        pub fn new() -> AbortController;

        #[wasm_bindgen(method, getter)]
        pub fn signal(this: &AbortController) -> AbortSignal;

        #[wasm_bindgen(method, js_name = abort)]
        pub fn abort(this: &AbortController, reason: JsValue);

        #[wasm_bindgen]
        pub type AbortSignal;

        #[wasm_bindgen(method, getter)]
        pub fn aborted(this: &AbortSignal) -> bool;
    }

    pub trait CancellationTokenExt {
        fn to_abort_controller(self) -> AbortController;
    }

    impl CancellationTokenExt for CancellationToken {
        fn to_abort_controller(self) -> AbortController {
            let controller = AbortController::new();

            let controller_clone = controller.clone();
            spawn_local(async move {
                console_log("===== waiting for cancellation".into());
                self.cancelled().await;
                console_log("===== Rust token cancelled".into());
                controller_clone.abort(JsValue::from("Rust token cancelled"));
                console_log("===== JS controller aborted".into());
            });

            controller
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    #[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
    #[cfg(target_arch = "wasm32")]
    async fn rust_cancellation_token_aborts_abort_controller() {
        use super::wasm::*;

        console_error_panic_hook::set_once();

        let token = CancellationToken::new();
        let controller: AbortController = token.clone().to_abort_controller();

        assert!(token.is_cancelled() == false);
        assert!(controller.signal().aborted() == false);

        token.cancel();

        console_log("===== Checking if token is cancelled".into());
        assert!(token.is_cancelled());
        console_log("===== Checking if controller is aborted".into());
        assert!(controller.signal().aborted());
    }

    #[wasm_bindgen_test]
    #[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
    async fn js_abort_controller_cancels_abort_controller() {
        console_error_panic_hook::set_once();

        // let token = CancellationToken::new();
        // let controller = AbortController::new();
        // let signal = controller.signal();

        // assert!(!token.is_cancelled());
        // assert!(!signal.is_aborted());

        // token.cancel();

        // assert!(token.is_cancelled());
        // assert!(signal.is_aborted());
    }
}
