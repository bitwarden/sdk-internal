use bitwarden_threading::cancellation_token::{
    wasm::{AbortController, AbortControllerExt, CancellationTokenExt},
    CancellationToken,
};
use bitwarden_threading::time::sleep;
use std::time::Duration;
use wasm_bindgen::externref_heap_live_count;
use wasm_bindgen_test::wasm_bindgen_test;

mod to_abort_controller {
    use super::*;

    #[wasm_bindgen_test]
    #[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
    #[cfg(target_arch = "wasm32")]
    async fn rust_cancel_propagates_to_js() {
        console_error_panic_hook::set_once();

        let token = CancellationToken::new();
        let controller: AbortController = token.clone().to_abort_controller();

        assert!(!token.is_cancelled());
        assert!(!controller.signal().aborted());

        token.cancel();
        // Give the cancellation some time to propagate
        sleep(Duration::from_millis(100)).await;

        assert!(token.is_cancelled());
        assert!(controller.signal().aborted());
    }

    #[wasm_bindgen_test]
    #[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
    #[cfg(target_arch = "wasm32")]
    async fn js_abort_does_not_propagate_to_rust() {
        console_error_panic_hook::set_once();

        let token = CancellationToken::new();
        let controller: AbortController = token.clone().to_abort_controller();

        assert!(!token.is_cancelled());
        assert!(!controller.signal().aborted());

        controller.abort(wasm_bindgen::JsValue::from("Test reason"));
        // Give the cancellation some time to propagate
        sleep(Duration::from_millis(100)).await;

        assert!(!token.is_cancelled());
        assert!(controller.signal().aborted());
    }
}

mod to_bidirectional_abort_controller {
    use super::*;

    #[wasm_bindgen_test]
    #[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
    #[cfg(target_arch = "wasm32")]
    async fn rust_cancel_propagates_to_js() {
        console_error_panic_hook::set_once();

        let token = CancellationToken::new();
        let (controller, _drop_guard) = token.clone().to_bidirectional_abort_controller();

        assert!(!token.is_cancelled());
        assert!(!controller.signal().aborted());

        token.cancel();
        // Give the cancellation some time to propagate
        sleep(Duration::from_millis(100)).await;

        assert!(token.is_cancelled());
        assert!(controller.signal().aborted());
    }

    #[wasm_bindgen_test]
    #[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
    #[cfg(target_arch = "wasm32")]
    async fn js_abort_propagates_to_rust() {
        console_error_panic_hook::set_once();

        let token = CancellationToken::new();
        let (controller, _drop_guard) = token.clone().to_bidirectional_abort_controller();

        assert!(!token.is_cancelled());
        assert!(!controller.signal().aborted());

        controller.abort(wasm_bindgen::JsValue::from("Test reason"));
        // Give the cancellation some time to propagate
        sleep(Duration::from_millis(100)).await;

        assert!(token.is_cancelled());
        assert!(controller.signal().aborted());
    }

    #[wasm_bindgen_test]
    #[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
    #[cfg(target_arch = "wasm32")]
    async fn rust_cancel_does_not_propagate_to_js_when_guard_has_been_dropped() {
        console_error_panic_hook::set_once();

        let token = CancellationToken::new();
        let (controller, drop_guard) = token.clone().to_bidirectional_abort_controller();

        assert!(!token.is_cancelled());
        assert!(!controller.signal().aborted());

        drop(drop_guard);
        sleep(Duration::from_millis(100)).await;

        token.cancel();
        sleep(Duration::from_millis(100)).await;

        assert!(token.is_cancelled());
        assert!(!controller.signal().aborted());
    }

    #[wasm_bindgen_test]
    #[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
    #[cfg(target_arch = "wasm32")]
    async fn drops_reference_to_js_controller_when_rust_token_is_dropped() {
        console_error_panic_hook::set_once();

        let token = CancellationToken::new();

        let heap_count_before_creating_abort_controller = externref_heap_live_count();

        let (_controller, drop_guard) = token.clone().to_bidirectional_abort_controller();
        let heap_count_after_creating_abort_controller = externref_heap_live_count();

        drop(drop_guard);
        // Give the drop some time to propagate
        sleep(Duration::from_millis(100)).await;
        let heap_count_after_dropping_guard = externref_heap_live_count();

        // Creating the AbortController create 2 strong references to the JS object.
        // One is kept internally to be able to propagate cancellations to the JS object and the
        // the other is returned to the caller.
        assert_eq!(
            heap_count_after_creating_abort_controller,
            heap_count_before_creating_abort_controller + 2
        );

        // Dropping the token should the internal strong reference to the JS object, leaving us
        // with only the strong reference that was returned to the caller.
        // We check this because the reference is kept within a spawn_local future and it'll only be
        // dropped when the future is dropped. And the future needs to be dropped or we'll leak memory.
        assert_eq!(
            heap_count_after_dropping_guard,
            heap_count_after_creating_abort_controller - 1,
            "Dropping the token should drop the internal strong reference to the JS object"
        );
    }
}

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

mod to_bidirectional_cancellation_token {
    use super::*;

    #[wasm_bindgen_test]
    #[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
    #[cfg(target_arch = "wasm32")]
    async fn rust_cancel_propagates_to_js() {
        console_error_panic_hook::set_once();

        let controller = AbortController::new();
        let (token, _drop_guard) = controller.clone().to_bidirectional_cancellation_token();

        assert!(!token.is_cancelled());
        assert!(!controller.signal().aborted());

        token.cancel();
        // Give the cancellation some time to propagate
        sleep(Duration::from_millis(100)).await;

        assert!(token.is_cancelled());
        assert!(controller.signal().aborted());
    }

    #[wasm_bindgen_test]
    #[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
    #[cfg(target_arch = "wasm32")]
    async fn js_abort_propagates_to_rust() {
        console_error_panic_hook::set_once();

        let controller = AbortController::new();
        let (token, _drop_guard) = controller.clone().to_bidirectional_cancellation_token();

        assert!(!token.is_cancelled());
        assert!(!controller.signal().aborted());

        controller.abort(wasm_bindgen::JsValue::from("Test reason"));
        // Give the cancellation some time to propagate
        sleep(Duration::from_millis(100)).await;

        assert!(token.is_cancelled());
        assert!(controller.signal().aborted());
    }

    #[wasm_bindgen_test]
    #[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
    #[cfg(target_arch = "wasm32")]
    async fn rust_cancel_does_not_propagate_to_js_when_guard_has_been_dropped() {
        console_error_panic_hook::set_once();

        let controller = AbortController::new();
        let (token, drop_guard) = controller.clone().to_bidirectional_cancellation_token();

        assert!(!token.is_cancelled());
        assert!(!controller.signal().aborted());

        drop(drop_guard);
        sleep(Duration::from_millis(100)).await;

        token.cancel();
        sleep(Duration::from_millis(100)).await;

        assert!(token.is_cancelled());
        assert!(!controller.signal().aborted());
    }

    #[wasm_bindgen_test]
    #[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
    #[cfg(target_arch = "wasm32")]
    async fn drops_reference_to_js_controller_when_rust_token_is_dropped() {
        console_error_panic_hook::set_once();

        let controller = AbortController::new();

        let heap_count_before_creating_cancellation_token = externref_heap_live_count();

        let (_token, drop_guard) = controller.clone().to_bidirectional_cancellation_token();
        let heap_count_after_creating_cancellation_token = externref_heap_live_count();

        drop(drop_guard);
        sleep(Duration::from_millis(100)).await;

        let heap_count_after_dropping_guard = externref_heap_live_count();

        // Creating the AbortController create 2 strong references to the JS object.
        // One is kept internally to be able to propagate cancellations to the JS object and the
        // the other is returned to the caller.
        assert_eq!(
            heap_count_after_creating_cancellation_token,
            heap_count_before_creating_cancellation_token + 1
        );

        // Dropping the token should the internal strong reference to the JS object, leaving us
        // with only the strong reference that was returned to the caller.
        // We check this because the reference is kept within a spawn_local future and it'll only be
        // dropped when the future is dropped. And the future needs to be dropped or we'll leak memory.
        assert_eq!(
            heap_count_after_dropping_guard, heap_count_before_creating_cancellation_token,
            "Dropping the token should drop the internal strong reference to the JS object"
        );
    }
}
