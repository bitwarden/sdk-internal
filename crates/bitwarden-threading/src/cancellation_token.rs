pub use tokio_util::sync::CancellationToken;

#[cfg(target_arch = "wasm32")]
pub mod wasm {
    use tokio::select;
    use tokio_util::sync::DropGuard;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::spawn_local;

    use super::*;

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = console, js_name = log)]
        pub fn console_log(message: &str);

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
        /// Converts a `CancellationToken` to an `AbortController`.
        /// The signal only travels in one direction: `CancellationToken` -> `AbortController`,
        /// i.e. the `AbortController` will be aborted when the `CancellationToken` is cancelled.
        fn to_abort_controller(self) -> AbortController;
        fn to_bidirectional_abort_controller(self) -> (AbortController, DropGuard);
    }

    impl CancellationTokenExt for CancellationToken {
        fn to_abort_controller(self) -> AbortController {
            let controller = AbortController::new();

            let token_clone = self.clone();
            let controller_clone = controller.clone();

            let closure_dropped_token = CancellationToken::new();
            let drop_guard = closure_dropped_token.clone().drop_guard();

            spawn_local(async move {
                select! {
                    _ = token_clone.cancelled() => {
                        controller_clone.abort(JsValue::from("Rust token cancelled"));
                    },
                    _ = closure_dropped_token.cancelled() => {}
                }
            });

            let closure = Closure::new({
                let _drop_guard = drop_guard;
                move || {
                    // Do nothing
                }
            });
            controller.signal().add_event_listener("abort", &closure);
            closure.forget(); // Transfer ownership to the JS runtime

            controller
        }

        fn to_bidirectional_abort_controller(self) -> (AbortController, DropGuard) {
            let controller = AbortController::new();

            let drop_guard = connect_token_and_controller(self.clone(), controller.clone());

            (controller, drop_guard)
        }
    }

    pub trait AbortControllerExt {
        fn to_cancellation_token(&self) -> CancellationToken;
        fn to_bidirectional_cancellation_token(&self) -> (CancellationToken, DropGuard);
    }

    impl AbortControllerExt for AbortController {
        fn to_cancellation_token(&self) -> CancellationToken {
            let token = CancellationToken::new();

            let token_clone = token.clone();
            let closure = Closure::new(move || {
                token_clone.cancel();
            });
            self.signal().add_event_listener("abort", &closure);
            closure.forget(); // Transfer ownership to the JS runtime

            token
        }

        fn to_bidirectional_cancellation_token(&self) -> (CancellationToken, DropGuard) {
            let token = CancellationToken::new();

            let drop_guard = connect_token_and_controller(token.clone(), self.clone());

            (token, drop_guard)
        }
    }

    fn connect_token_and_controller(
        token: CancellationToken,
        controller: AbortController,
    ) -> DropGuard {
        let token_clone = token.clone();
        let controller_clone = controller.clone();

        let guarded_token = CancellationToken::new();
        let drop_guard = guarded_token.clone().drop_guard();

        spawn_local(async move {
            select! {
                _ = token_clone.cancelled() => {
                    controller_clone.abort(JsValue::from("Rust token cancelled"));
                },
                _ = guarded_token.cancelled() => {}
            }
        });

        let closure = Closure::new(move || {
            token.cancel();
        });
        controller.signal().add_event_listener("abort", &closure);
        closure.forget(); // Transfer ownership to the JS runtime

        drop_guard
    }
}
