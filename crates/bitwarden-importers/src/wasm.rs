//! WASM bindings for the direct 1Password import.
//!
//! The import asks the user for a TOTP code mid sign-in, which `wasm_bindgen` cannot express as the
//! `&dyn OnePasswordTwoFactorUi` the native API takes. JavaScript passes an object implementing
//! [`OnePasswordTwoFactorUi`](RawJsOnePasswordTwoFactorUi) instead, and
//! [`JsOnePasswordTwoFactorUi`] adapts it back to the trait.

use bitwarden_threading::ThreadBoundRunner;
use wasm_bindgen::prelude::*;

use crate::{OnePasswordTotpResult, OnePasswordTwoFactorUi};

#[wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
/**
 * Asks the user for a 1Password two-step verification code during a direct import.
 */
export interface OnePasswordTwoFactorUi {
    /**
     * Provides a TOTP passcode for the given zero-based attempt. A wrong code restarts the
     * sign-in, so `attempt` grows as the user retries.
     *
     * @returns the passcode, or undefined if the user declined to provide one.
     */
    provideTotp(attempt: number): Promise<string | undefined>;
}
"#;

#[wasm_bindgen]
extern "C" {
    /// The JavaScript object implementing the two-factor prompt.
    #[wasm_bindgen(js_name = OnePasswordTwoFactorUi, typescript_type = "OnePasswordTwoFactorUi")]
    pub type RawJsOnePasswordTwoFactorUi;

    #[wasm_bindgen(catch, method, structural, js_name = provideTotp)]
    async fn provide_totp(
        this: &RawJsOnePasswordTwoFactorUi,
        attempt: u32,
    ) -> Result<JsValue, JsValue>;
}

/// Adapts the JavaScript prompt to [`OnePasswordTwoFactorUi`].
///
/// The JS object is `!Send`, so it stays pinned to its own thread behind a [`ThreadBoundRunner`];
/// only the runner's channel handle crosses threads, which is what makes this `Send + Sync`.
pub(crate) struct JsOnePasswordTwoFactorUi(ThreadBoundRunner<RawJsOnePasswordTwoFactorUi>);

impl JsOnePasswordTwoFactorUi {
    pub(crate) fn new(ui: RawJsOnePasswordTwoFactorUi) -> Self {
        Self(ThreadBoundRunner::new(ui))
    }
}

#[async_trait::async_trait]
impl OnePasswordTwoFactorUi for JsOnePasswordTwoFactorUi {
    async fn provide_totp(&self, attempt: u32) -> OnePasswordTotpResult {
        let code = self
            .0
            .run_in_thread(move |ui| async move {
                ui.provide_totp(attempt)
                    .await
                    .ok()
                    .and_then(|code| code.as_string())
            })
            .await;

        // A value that isn't a string, a rejected promise, and a runner whose thread went away all
        // leave the sign-in without a code, which is what cancelling it means.
        match code {
            Ok(Some(code)) => OnePasswordTotpResult::Code(code),
            Ok(None) | Err(_) => OnePasswordTotpResult::Cancel,
        }
    }
}
