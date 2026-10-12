//! WASM bindings for the direct 1Password import.
//!
//! The import calls back into the user mid sign-in: for a TOTP code, or for the single sign-on
//! browser step and device approval. `wasm_bindgen` cannot express these as the `&dyn` callbacks
//! the native API takes. JavaScript passes objects implementing the interfaces
//! declared below instead, and the `Js*` types adapt them back to the traits.

use async_trait::async_trait;
use bitwarden_threading::ThreadBoundRunner;
use wasm_bindgen::prelude::*;

use crate::{
    OnePasswordSsoEnrollment, OnePasswordSsoEnrollmentResult, OnePasswordSsoEnrollmentStatus,
    OnePasswordSsoLoginResult, OnePasswordSsoUi, OnePasswordTotpResult, OnePasswordTwoFactorUi,
    OnePasswordVerificationCodeResult,
};

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

/**
 * Takes the user through a 1Password single sign-on login during a direct import.
 */
export interface OnePasswordSsoUi {
    /**
     * Opens `ssoLoginUrl`, usually in a browser, and waits for the identity provider to redirect
     * to `redirectTo`.
     *
     * @returns the full URL the identity provider redirected to, or undefined if the user gave up.
     */
    performSsoLogin(ssoLoginUrl: string, redirectTo: string): Promise<string | undefined>;

    /**
     * Shows the device enrollment UI. Called once per import: every import is a new device.
     */
    beginSsoEnrollment(): Promise<OnePasswordSsoEnrollment>;
}

/**
 * A device enrollment in progress. `endEnrollment` is called exactly once when it ends, unless the
 * import is dropped halfway.
 */
export interface OnePasswordSsoEnrollment {
    /**
     * Resolves when the user cancels the enrollment; a rejection counts as a cancellation. Keep it
     * pending while the enrollment runs, and settle it once `endEnrollment` is called so the
     * object can be released.
     */
    cancelled(): Promise<void>;

    /** Shows the stage the enrollment has reached. */
    updateStatus(status: OnePasswordSsoEnrollmentStatus, message: string): Promise<void>;

    /**
     * Asks for the verification code the approving device shows.
     *
     * @returns the code, or undefined if the user declined to provide one.
     */
    provideVerificationCode(): Promise<string | undefined>;

    /** Closes the enrollment UI. */
    endEnrollment(result: OnePasswordSsoEnrollmentResult): Promise<void>;
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

#[wasm_bindgen]
extern "C" {
    /// The JavaScript object implementing the single sign-on prompts.
    #[wasm_bindgen(js_name = OnePasswordSsoUi, typescript_type = "OnePasswordSsoUi")]
    pub type RawJsOnePasswordSsoUi;

    #[wasm_bindgen(catch, method, structural, js_name = performSsoLogin)]
    async fn perform_sso_login(
        this: &RawJsOnePasswordSsoUi,
        sso_login_url: &str,
        redirect_to: &str,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch, method, structural, js_name = beginSsoEnrollment)]
    async fn begin_sso_enrollment(
        this: &RawJsOnePasswordSsoUi,
    ) -> Result<RawJsOnePasswordSsoEnrollment, JsValue>;

    /// The JavaScript object implementing a device enrollment in progress.
    #[wasm_bindgen(js_name = OnePasswordSsoEnrollment, typescript_type = "OnePasswordSsoEnrollment")]
    pub type RawJsOnePasswordSsoEnrollment;

    #[wasm_bindgen(catch, method, structural, js_name = cancelled)]
    async fn cancelled(this: &RawJsOnePasswordSsoEnrollment) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch, method, structural, js_name = updateStatus)]
    async fn update_status(
        this: &RawJsOnePasswordSsoEnrollment,
        status: OnePasswordSsoEnrollmentStatus,
        message: &str,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch, method, structural, js_name = provideVerificationCode)]
    async fn provide_verification_code(
        this: &RawJsOnePasswordSsoEnrollment,
    ) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(catch, method, structural, js_name = endEnrollment)]
    async fn end_enrollment(
        this: &RawJsOnePasswordSsoEnrollment,
        result: OnePasswordSsoEnrollmentResult,
    ) -> Result<JsValue, JsValue>;
}

/// Adapts the JavaScript single sign-on prompts to [`OnePasswordSsoUi`], pinned to their thread
/// like [`JsOnePasswordTwoFactorUi`].
pub(crate) struct JsOnePasswordSsoUi(ThreadBoundRunner<RawJsOnePasswordSsoUi>);

impl JsOnePasswordSsoUi {
    pub(crate) fn new(ui: RawJsOnePasswordSsoUi) -> Self {
        Self(ThreadBoundRunner::new(ui))
    }
}

#[async_trait]
impl OnePasswordSsoUi for JsOnePasswordSsoUi {
    async fn perform_sso_login(
        &self,
        sso_login_url: &str,
        redirect_to: &str,
    ) -> OnePasswordSsoLoginResult {
        let sso_login_url = sso_login_url.to_owned();
        let redirect_to = redirect_to.to_owned();
        let redirected_to = self
            .0
            .run_in_thread(move |ui| async move {
                ui.perform_sso_login(&sso_login_url, &redirect_to)
                    .await
                    .ok()
                    .and_then(|url| url.as_string())
            })
            .await;

        match redirected_to {
            Ok(Some(url)) => OnePasswordSsoLoginResult::RedirectedTo(url),
            Ok(None) | Err(_) => OnePasswordSsoLoginResult::Cancel,
        }
    }

    async fn begin_sso_enrollment(&self) -> Box<dyn OnePasswordSsoEnrollment> {
        // The enrollment object is `!Send` too, so its runner is created on the JS thread and only
        // the runner comes back.
        let enrollment = self
            .0
            .run_in_thread(|ui| async move {
                let enrollment = ui.begin_sso_enrollment().await.ok()?;
                Some(ThreadBoundRunner::new(enrollment))
            })
            .await;

        match enrollment {
            Ok(Some(runner)) => Box::new(JsOnePasswordSsoEnrollment(runner)),
            Ok(None) | Err(_) => Box::new(CancelledEnrollment),
        }
    }
}

/// Adapts the JavaScript enrollment object to [`OnePasswordSsoEnrollment`].
struct JsOnePasswordSsoEnrollment(ThreadBoundRunner<RawJsOnePasswordSsoEnrollment>);

#[async_trait]
impl OnePasswordSsoEnrollment for JsOnePasswordSsoEnrollment {
    async fn cancelled(&self) {
        // Failing closed: a rejection or a dead runner cancels the enrollment like the user would.
        let _ = self
            .0
            .run_in_thread(|enrollment| async move {
                let _ = enrollment.cancelled().await;
            })
            .await;
    }

    async fn update_status(&self, status: OnePasswordSsoEnrollmentStatus, message: &str) {
        let message = message.to_owned();
        let _ = self
            .0
            .run_in_thread(move |enrollment| async move {
                let _ = enrollment.update_status(status, &message).await;
            })
            .await;
    }

    async fn provide_verification_code(&self) -> OnePasswordVerificationCodeResult {
        let code = self
            .0
            .run_in_thread(|enrollment| async move {
                enrollment
                    .provide_verification_code()
                    .await
                    .ok()
                    .and_then(|code| code.as_string())
            })
            .await;

        match code {
            Ok(Some(code)) => OnePasswordVerificationCodeResult::Code(code),
            Ok(None) | Err(_) => OnePasswordVerificationCodeResult::Cancel,
        }
    }

    async fn end_enrollment(&self, result: OnePasswordSsoEnrollmentResult) {
        let _ = self
            .0
            .run_in_thread(move |enrollment| async move {
                let _ = enrollment.end_enrollment(result).await;
            })
            .await;
    }
}

/// The enrollment of a UI that could not show one, which cancels it right away.
struct CancelledEnrollment;

#[async_trait]
impl OnePasswordSsoEnrollment for CancelledEnrollment {
    async fn cancelled(&self) {}

    async fn update_status(&self, _status: OnePasswordSsoEnrollmentStatus, _message: &str) {}

    async fn provide_verification_code(&self) -> OnePasswordVerificationCodeResult {
        OnePasswordVerificationCodeResult::Cancel
    }

    async fn end_enrollment(&self, _result: OnePasswordSsoEnrollmentResult) {}
}
