pub use tokio_util::sync::CancellationToken;

#[cfg(target_arch = "wasm32")]
pub mod wasm {
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::spawn_local;

    use super::*;

    #[wasm_bindgen]
    extern "C" {
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

        #[wasm_bindgen(method, js_name = addEventListener)]
        pub fn add_event_listener(
            this: &AbortSignal,
            event_type: &str,
            callback: &Closure<dyn FnMut()>,
        );
    }

    pub trait CancellationTokenExt {
        fn to_abort_controller(self) -> AbortController;
    }

    impl CancellationTokenExt for CancellationToken {
        fn to_abort_controller(self) -> AbortController {
            let controller = AbortController::new();

            connect_token_and_controller(self.clone(), controller.clone());

            controller
        }
    }

    pub trait AbortControllerExt {
        fn to_cancellation_token(&self) -> CancellationToken;
    }

    impl AbortControllerExt for AbortController {
        fn to_cancellation_token(&self) -> CancellationToken {
            let token = CancellationToken::new();

            connect_token_and_controller(token.clone(), self.clone());

            token
        }
    }

    fn connect_token_and_controller(token: CancellationToken, controller: AbortController) {
        let token_clone = token.clone();
        let controller_clone = controller.clone();
        spawn_local(async move {
            token_clone.cancelled().await;
            controller_clone.abort(JsValue::from("Rust token cancelled"));
        });

        let closure = Closure::new(move || {
            token.cancel();
        });
        controller.signal().add_event_listener("abort", &closure);
        closure.forget(); // Transfer ownership to the JS runtime
    }
}
