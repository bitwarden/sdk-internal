pub use tokio_util::sync::CancellationToken;

#[cfg(feature = "wasm")]
pub mod wasm {
    use wasm_bindgen::prelude::*;

    use super::*;

    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(typescript_type = AbortController)]
        #[derive(Clone)]
        pub type AbortController;

        #[wasm_bindgen(constructor)]
        pub fn new() -> AbortController;

        #[wasm_bindgen(method, getter)]
        pub fn signal(this: &AbortController) -> AbortSignal;

        #[wasm_bindgen(method, js_name = abort)]
        pub fn abort(this: &AbortController, reason: JsValue);

        #[wasm_bindgen(typescript_type = AbortSignal)]
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

    pub trait AbortControllerExt {
        /// Converts an `AbortController` to a `CancellationToken`.
        /// The signal only travels in one direction: `AbortController` -> `CancellationToken`,
        /// i.e. the `CancellationToken` will be cancelled when the `AbortController` is aborted
        /// but not the other way around.
        fn to_cancellation_token(&self) -> CancellationToken;
    }

    impl AbortControllerExt for AbortController {
        fn to_cancellation_token(&self) -> CancellationToken {
            self.signal().to_cancellation_token()
        }
    }

    pub trait AbortSignalExt {
        /// Converts an `AbortSignal` to a `CancellationToken`.
        /// The signal only travels in one direction: `AbortSignal` -> `CancellationToken`,
        /// i.e. the `CancellationToken` will be cancelled when the `AbortSignal` is aborted
        /// but not the other way around.
        fn to_cancellation_token(&self) -> CancellationToken;
    }

    impl AbortSignalExt for AbortSignal {
        fn to_cancellation_token(&self) -> CancellationToken {
            let token = CancellationToken::new();

            let token_clone = token.clone();
            let closure = Closure::new(move || {
                token_clone.cancel();
            });
            self.add_event_listener("abort", &closure);
            closure.forget(); // Transfer ownership to the JS runtime

            token
        }
    }
}
