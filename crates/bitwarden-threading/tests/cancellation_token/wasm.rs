use bitwarden_threading::cancellation_token::{
    wasm::{AbortController, AbortControllerExt, CancellationTokenExt},
    CancellationToken,
};
use bitwarden_threading::sleep;
use std::time::Duration;
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen_test]
#[allow(dead_code)] // Not actually dead, but rust-analyzer doesn't understand `wasm_bindgen_test`
#[cfg(target_arch = "wasm32")]
async fn rust_cancellation_token_aborts_abort_controller() {
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
async fn js_abort_controller_cancels_abort_controller() {
    console_error_panic_hook::set_once();

    let controller = AbortController::new();
    let token: CancellationToken = controller.to_cancellation_token();

    assert!(!token.is_cancelled());
    assert!(!controller.signal().aborted());

    controller.abort(wasm_bindgen::JsValue::from("Test reason"));
    // Give the cancellation some time to propagate
    sleep(Duration::from_millis(100)).await;

    assert!(token.is_cancelled());
    assert!(controller.signal().aborted());
}
