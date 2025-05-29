#![allow(unused_imports)] // Rust analyzer doesn't understand the `wasm_bindgen_test` macro
use std::time::Duration;

use bitwarden_threading::{
    cancellation_token::wasm::{AbortController, AbortControllerExt},
    time::sleep,
};
use wasm_bindgen_test::wasm_bindgen_test;

mod to_cancellation_token {
    use super::*;

    #[wasm_bindgen_test]
    #[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
    #[cfg(target_arch = "wasm32")]
    async fn rust_cancel_does_not_propagate_to_js() {
        console_error_panic_hook::set_once();

        let controller = AbortController::new();
        let token = controller.clone().to_cancellation_token();

        assert!(!token.is_cancelled());
        assert!(!controller.signal().aborted());

        token.cancel();
        // Give the cancellation some time to propagate
        sleep(Duration::from_millis(100)).await;

        assert!(token.is_cancelled());
        assert!(!controller.signal().aborted());
    }

    #[wasm_bindgen_test]
    #[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
    #[cfg(target_arch = "wasm32")]
    async fn js_abort_propagate_to_rust() {
        console_error_panic_hook::set_once();

        let controller = AbortController::new();
        let token = controller.clone().to_cancellation_token();

        assert!(!token.is_cancelled());
        assert!(!controller.signal().aborted());

        controller.abort(wasm_bindgen::JsValue::from("Test reason"));
        // Give the cancellation some time to propagate
        sleep(Duration::from_millis(100)).await;

        assert!(token.is_cancelled());
        assert!(controller.signal().aborted());
    }
}
