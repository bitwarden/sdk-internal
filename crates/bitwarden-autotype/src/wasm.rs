//! WASM bindings for the autotype IPC requests, exposed to the clients through
//! `@bitwarden/sdk-internal`.

use bitwarden_ipc::{
    Endpoint, IpcClientExt, RequestError, RpcHandler, RpcRequest, wasm::JsIpcClient,
};
use bitwarden_threading::{
    ThreadBoundRunner,
    cancellation_token::wasm::{AbortSignal, AbortSignalExt},
};
use serde::{Deserialize, Serialize};
use tsify::Tsify;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};

#[wasm_bindgen(typescript_custom_section)]
const TS_AUTOTYPE_TYPES: &'static str = r#"
export interface AutotypeDriver {
    /**
     * Enable or disable autotype. Returns if setting
     * the enabled state was successful or not.
     */
    set_autotype_enabled(enabled: boolean): Promise<boolean>;

    /**
     * Set the keyboard shortcut. Returns a boolean representing
     * if setting the shortcut was successful or not.
     */
    set_autotype_keyboard_shortcut(shortcut: string[]): Promise<boolean>;
}
"#;

#[wasm_bindgen]
extern "C" {
    /// JavaScript implementation of the platform Autotype operations.
    #[wasm_bindgen(js_name = AutotypeDriver, typescript_type = "AutotypeDriver")]
    pub type RawJsAutotypeDriver;

    /// Enable or disable autotype. Returns if setting the enabled state was successful or not.
    #[wasm_bindgen(method, catch)]
    async fn set_autotype_enabled(
        this: &RawJsAutotypeDriver,
        enabled: bool,
    ) -> Result<JsValue, JsValue>;

    /// Set the autotype keyboard shortcut. Returns a boolean
    /// representing if setting the shortcut was successful or not.
    #[wasm_bindgen(method, catch)]
    async fn set_autotype_keyboard_shortcut(
        this: &RawJsAutotypeDriver,
        shortcut: Vec<String>,
    ) -> Result<JsValue, JsValue>;
}

/// Wraps the JavaScript driver in a [`ThreadBoundRunner`] so it can be used from the `Send`
/// futures an [`RpcHandler`] is required to return.
struct JsAutotypeDriver {
    runner: ThreadBoundRunner<RawJsAutotypeDriver>,
}

impl JsAutotypeDriver {
    fn new(runner: ThreadBoundRunner<RawJsAutotypeDriver>) -> Self {
        Self { runner }
    }

    /// Asks the driver to enable or disable autotype, returning whether the change was applied.
    ///
    /// A driver that throws, returns a non-boolean, or cannot be reached is reported as `false`:
    /// the change is only ever reported as successful when the driver says so.
    async fn set_autotype_enabled(&self, enabled: bool) -> bool {
        self.runner
            .run_in_thread(move |driver| async move {
                driver
                    .set_autotype_enabled(enabled)
                    .await
                    .ok()
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false)
            })
            .await
            .unwrap_or(false)
    }

    /// Asks the driver to change the keyboard shortcut, returning whether the change was applied.
    ///
    /// The shortcut is passed through untouched: the driver owns what counts as a valid
    /// combination, and reports an unusable one as `false`. Failures fold into `false` the same
    /// way [`Self::set_autotype_enabled`] does.
    async fn set_autotype_keyboard_shortcut(&self, shortcut: Vec<String>) -> bool {
        self.runner
            .run_in_thread(move |driver| async move {
                driver
                    .set_autotype_keyboard_shortcut(shortcut)
                    .await
                    .ok()
                    .and_then(|value| value.as_bool())
                    .unwrap_or(false)
            })
            .await
            .unwrap_or(false)
    }
}

/// A request asking the receiving client to enable or disable Autotype.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutotypeSetEnabledRequest {
    /// Whether autotype should be enabled.
    pub enabled: bool,
}

/// A response to an [`AutotypeSetEnabledRequest`].
#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct AutotypeSetEnabledResponse {
    /// Whether the requested change for enabling/disabling Autotype was applied.
    pub success: bool,
}

impl RpcRequest for AutotypeSetEnabledRequest {
    type Response = AutotypeSetEnabledResponse;

    const NAME: &str = "AutotypeSetEnabledRequest";
}

/// An [`RpcHandler`] that applies the requested state through a [`RawJsAutotypeDriver`].
struct AutotypeSetEnabledHandler {
    driver: JsAutotypeDriver,
}

impl AutotypeSetEnabledHandler {
    fn new(driver: JsAutotypeDriver) -> Self {
        Self { driver }
    }
}

impl RpcHandler for AutotypeSetEnabledHandler {
    type Request = AutotypeSetEnabledRequest;

    async fn handle(&self, request: Self::Request) -> AutotypeSetEnabledResponse {
        AutotypeSetEnabledResponse {
            success: self.driver.set_autotype_enabled(request.enabled).await,
        }
    }
}

/// A request asking the receiving client to change the keyboard shortcut Autotype is triggered by.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutotypeSetKeyboardShortcutRequest {
    /// The shortcut to use, as its individual keys — modifiers first, the base key last. Carried
    /// through unvalidated; the receiving client decides what it accepts.
    pub shortcut: Vec<String>,
}

/// A response to an [`AutotypeSetKeyboardShortcutRequest`].
#[derive(Debug, Clone, Serialize, Deserialize, Tsify)]
#[tsify(into_wasm_abi, from_wasm_abi)]
pub struct AutotypeSetKeyboardShortcutResponse {
    /// Whether the requested keyboard shortcut was applied.
    pub success: bool,
}

impl RpcRequest for AutotypeSetKeyboardShortcutRequest {
    type Response = AutotypeSetKeyboardShortcutResponse;

    const NAME: &str = "AutotypeSetKeyboardShortcutRequest";
}

/// An [`RpcHandler`] that applies the requested shortcut through a [`RawJsAutotypeDriver`].
struct AutotypeSetKeyboardShortcutHandler {
    driver: JsAutotypeDriver,
}

impl AutotypeSetKeyboardShortcutHandler {
    fn new(driver: JsAutotypeDriver) -> Self {
        Self { driver }
    }
}

impl RpcHandler for AutotypeSetKeyboardShortcutHandler {
    type Request = AutotypeSetKeyboardShortcutRequest;

    async fn handle(&self, request: Self::Request) -> AutotypeSetKeyboardShortcutResponse {
        AutotypeSetKeyboardShortcutResponse {
            success: self
                .driver
                .set_autotype_keyboard_shortcut(request.shortcut)
                .await,
        }
    }
}

/// Registers the handlers so that the client responds to Autotype requests by driving the platform
/// Autotype implementation through the supplied [`RawJsAutotypeDriver`].
///
/// This belongs within the desktop main process, which owns the global shortcut. Every handler
/// shares one runner, so all of them reach the same driver instance.
#[wasm_bindgen(js_name = autotypeRegisterHandlers)]
pub async fn autotype_register_handlers(ipc_client: &JsIpcClient, driver: RawJsAutotypeDriver) {
    let runner = ThreadBoundRunner::new(driver);

    ipc_client
        .client
        .register_rpc_handler(AutotypeSetEnabledHandler::new(JsAutotypeDriver::new(
            runner.clone(),
        )))
        .await;
    ipc_client
        .client
        .register_rpc_handler(AutotypeSetKeyboardShortcutHandler::new(
            JsAutotypeDriver::new(runner),
        ))
        .await;
}

/// Sends an `AutotypeSetEnabledRequest` to the desktop main process and reports whether the
/// requested change was successful.
#[wasm_bindgen(js_name = autotypeRequestSetEnabled)]
pub async fn autotype_request_set_enabled(
    ipc_client: &JsIpcClient,
    enabled: bool,
    abort_signal: Option<AbortSignal>,
) -> Result<AutotypeSetEnabledResponse, RequestError> {
    ipc_client
        .client
        .request(
            AutotypeSetEnabledRequest { enabled },
            Endpoint::DesktopMain,
            abort_signal.map(|signal| signal.to_cancellation_token()),
        )
        .await
}

/// Sends an `AutotypeSetKeyboardShortcutRequest` to the desktop main process and reports whether
/// the requested shortcut was applied.
#[wasm_bindgen(js_name = autotypeRequestSetKeyboardShortcut)]
pub async fn autotype_request_set_keyboard_shortcut(
    ipc_client: &JsIpcClient,
    shortcut: Vec<String>,
    abort_signal: Option<AbortSignal>,
) -> Result<AutotypeSetKeyboardShortcutResponse, RequestError> {
    ipc_client
        .client
        .request(
            AutotypeSetKeyboardShortcutRequest { shortcut },
            Endpoint::DesktopMain,
            abort_signal.map(|signal| signal.to_cancellation_token()),
        )
        .await
}
