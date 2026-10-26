//! WASM bindings for the autotype IPC requests, exposed to the clients through
//! `@bitwarden/sdk-internal`.
//!
//! The `AutotypeDriver` interface is implemented by the user of this crate (for
//! example, within the Bitwarden desktop app).

use bitwarden_ipc::{
    Endpoint, IpcClientExt, RequestError, RpcHandler, RpcRequest, RpcRequestInfo, Source,
    wasm::JsIpcClient,
};
use bitwarden_threading::{
    ThreadBoundRunner,
    cancellation_token::wasm::{AbortSignal, AbortSignalExt},
};
use serde::{Deserialize, Serialize};
use tsify::serde_wasm_bindgen;
use wasm_bindgen::{JsCast, JsValue, prelude::wasm_bindgen};
use wasm_bindgen_futures::js_sys;

#[wasm_bindgen(typescript_custom_section)]
/// `TS_AUTOTYPE_TYPES` defines the TypeScript types for bindgen.
/// The AutotypeDriver interface is a TS interface that will be implemented
/// by the user of this crate (e.g. in the Bitwarden desktop app).
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

    /**
     * List the applications currently running. Returns an empty
     * array if none could be determined. Entries that do not match
     * `AutotypeRunningApp` are skipped.
     */
    list_running_apps(): Promise<AutotypeRunningApp[]>;
}
"#;

#[wasm_bindgen]
extern "C" {
    /// JavaScript implementation of the various Autotype operations.
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

    /// List the applications currently running. The driver returns an `AutotypeRunningApp[]`,
    /// received here as a raw `JsValue` so `JsAutotypeDriver::list_running_apps` can skip
    /// entries that don't match `AutotypeRunningApp`.
    #[wasm_bindgen(method, catch)]
    async fn list_running_apps(this: &RawJsAutotypeDriver) -> Result<JsValue, JsValue>;
}

/// A running application.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[bitwarden_ffi::wasm_record]
pub struct AutotypeRunningApp {
    /// Human-readable name for the app, e.g. `Google Chrome`.
    pub name: String,
    /// Path to the app's executable.
    pub path: String,
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

    /// Sets the Autotype enabled state, and returns if setting the
    /// enabled state was successful or not.
    async fn set_autotype_enabled(&self, enabled: bool) -> bool {
        self.runner
            .run_in_thread(move |driver| async move {
                match driver.set_autotype_enabled(enabled).await {
                    Ok(value) => value.as_bool().unwrap_or_else(|| {
                        tracing::error!(
                            "Autotype driver returned a non-boolean set-enabled result"
                        );
                        false
                    }),
                    Err(error) => {
                        tracing::error!(?error, "Autotype driver failed to set the enabled state");
                        false
                    }
                }
            })
            .await
            .unwrap_or_else(|error| {
                tracing::error!(?error, "Autotype runner failed to set the enabled state");
                false
            })
    }

    /// Sets the keyboard shortcut used for executing Autotype.
    /// Returns if setting the keyboard shortcut was successful or not.
    async fn set_autotype_keyboard_shortcut(&self, shortcut: Vec<String>) -> bool {
        self.runner
            .run_in_thread(move |driver| async move {
                match driver.set_autotype_keyboard_shortcut(shortcut).await {
                    Ok(value) => value.as_bool().unwrap_or_else(|| {
                        tracing::error!("Autotype driver returned a non-boolean shortcut result");
                        false
                    }),
                    Err(error) => {
                        tracing::error!(?error, "Autotype driver failed to set the shortcut");
                        false
                    }
                }
            })
            .await
            .unwrap_or_else(|error| {
                tracing::error!(?error, "Autotype runner failed to set the shortcut");
                false
            })
    }

    /// Retrieves the currently running apps.
    /// Returns a Vec of `AutotypeRunningApp`. Apps that don't match the
    /// `AutotypeRunningApp` model are filtered out.
    async fn list_running_apps(&self) -> Vec<AutotypeRunningApp> {
        self.runner
            .run_in_thread(|driver| async move {
                let value = match driver.list_running_apps().await {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::error!(?error, "Autotype driver failed to list running apps");
                        return Vec::new();
                    }
                };

                // This converts value (a `JsValue`) into an Array.
                // This is critical for rejecting `null`, `undefined`, and other non-array values
                // that could have been passed from the JavaScript side.
                let Ok(array) = value.dyn_into::<js_sys::Array>() else {
                    tracing::warn!("Autotype driver returned a non-array of running apps");
                    return Vec::new();
                };

                // Filter through `array`, keeping entries that deserialize correctly
                // into the `AutotypeRunningApp` type. This filters out (skips) bad entries.
                array
                    .iter()
                    .filter_map(|entry| match serde_wasm_bindgen::from_value(entry) {
                        Ok(app) => Some(app),
                        Err(error) => {
                            tracing::warn!(
                                ?error,
                                "Autotype driver returned a malformed running app; skipping it"
                            );
                            None
                        }
                    })
                    .collect()
            })
            .await
            .unwrap_or_else(|error| {
                tracing::error!(?error, "Autotype runner failed to list running apps");
                Vec::new()
            })
    }
}

/// Determines if a request came from the desktop render process.
///
/// A rejection is logged with the request's
/// [`RpcRequest::NAME`] and the source it came from.
fn from_renderer(info: &RpcRequestInfo, request: &str) -> bool {
    let allowed = matches!(info.source, Source::DesktopRenderer);

    if !allowed {
        tracing::warn!(
            request,
            source = ?info.source,
            "Autotype rejected a request from a non-renderer source"
        );
    }
    allowed
}

/// A request asking the receiving client to enable or disable Autotype.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutotypeSetEnabledRequest {
    /// Whether autotype should be enabled.
    pub enabled: bool,
}

/// A response to an [`AutotypeSetEnabledRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[bitwarden_ffi::wasm_record]
pub struct AutotypeSetEnabledResponse {
    /// Whether the requested change for enabling/disabling Autotype was applied.
    pub success: bool,
}

impl RpcRequest for AutotypeSetEnabledRequest {
    type Response = AutotypeSetEnabledResponse;

    const NAME: &str = "AutotypeSetEnabledRequest";
}

/// An [`RpcHandler`] that applies the requested state through a [`RawJsAutotypeDriver`].
///
/// Only requests from the desktop renderer are applied; any other source is refused with
/// `success: false` before the driver is called. See [`from_renderer`].
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

    async fn handle(
        &self,
        request: Self::Request,
        info: RpcRequestInfo,
    ) -> AutotypeSetEnabledResponse {
        if !from_renderer(&info, Self::Request::NAME) {
            return AutotypeSetEnabledResponse { success: false };
        }

        AutotypeSetEnabledResponse {
            success: self.driver.set_autotype_enabled(request.enabled).await,
        }
    }
}

/// A request asking the receiving client to change the keyboard shortcut Autotype is triggered by.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutotypeSetKeyboardShortcutRequest {
    /// The shortcut used to execute Autotype.
    pub shortcut: Vec<String>,
}

/// A response to an [`AutotypeSetKeyboardShortcutRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[bitwarden_ffi::wasm_record]
pub struct AutotypeSetKeyboardShortcutResponse {
    /// Whether the requested keyboard shortcut was applied.
    pub success: bool,
}

impl RpcRequest for AutotypeSetKeyboardShortcutRequest {
    type Response = AutotypeSetKeyboardShortcutResponse;

    const NAME: &str = "AutotypeSetKeyboardShortcutRequest";
}

/// An [`RpcHandler`] that applies the requested shortcut through a [`RawJsAutotypeDriver`].
///
/// Only requests from the desktop renderer are applied; any other source is refused with
/// `success: false` before the shortcut reaches the driver. See [`from_renderer`].
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

    async fn handle(
        &self,
        request: Self::Request,
        info: RpcRequestInfo,
    ) -> AutotypeSetKeyboardShortcutResponse {
        if !from_renderer(&info, Self::Request::NAME) {
            return AutotypeSetKeyboardShortcutResponse { success: false };
        }

        AutotypeSetKeyboardShortcutResponse {
            success: self
                .driver
                .set_autotype_keyboard_shortcut(request.shortcut)
                .await,
        }
    }
}

/// A request asking the receiving client for the applications that are currently running.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutotypeListRunningAppsRequest;

/// A response to an [`AutotypeListRunningAppsRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[bitwarden_ffi::wasm_record]
pub struct AutotypeListRunningAppsResponse {
    /// The applications currently running.
    pub apps: Vec<AutotypeRunningApp>,
}

impl RpcRequest for AutotypeListRunningAppsRequest {
    type Response = AutotypeListRunningAppsResponse;

    const NAME: &str = "AutotypeListRunningAppsRequest";
}

/// An [`RpcHandler`] that lists running applications through a [`RawJsAutotypeDriver`].
///
/// Only requests from the desktop renderer are answered; any other source gets an empty list
/// without the driver being asked to enumerate anything. See [`from_renderer`].
struct AutotypeListRunningAppsHandler {
    driver: JsAutotypeDriver,
}

impl AutotypeListRunningAppsHandler {
    fn new(driver: JsAutotypeDriver) -> Self {
        Self { driver }
    }
}

impl RpcHandler for AutotypeListRunningAppsHandler {
    type Request = AutotypeListRunningAppsRequest;

    async fn handle(
        &self,
        _: Self::Request,
        info: RpcRequestInfo,
    ) -> AutotypeListRunningAppsResponse {
        if !from_renderer(&info, Self::Request::NAME) {
            return AutotypeListRunningAppsResponse { apps: Vec::new() };
        }

        AutotypeListRunningAppsResponse {
            apps: self.driver.list_running_apps().await,
        }
    }
}

/// This registers the Autotype handlers so the client responds to Autotype requests through
/// the `RawJsAutotypeDriver`.
#[bitwarden_ffi::wasm_export(js_name = registerAutotypeHandlers)]
pub async fn register_autotype_handlers(ipc_client: &JsIpcClient, driver: RawJsAutotypeDriver) {
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
            JsAutotypeDriver::new(runner.clone()),
        ))
        .await;
    ipc_client
        .client
        .register_rpc_handler(AutotypeListRunningAppsHandler::new(JsAutotypeDriver::new(
            runner,
        )))
        .await;
}

/// Sends an `AutotypeSetEnabledRequest` to the desktop main process and reports whether the
/// requested change was successful.
///
/// There is no built-in timeout: the request waits until main responds or `abort_signal` aborts,
/// so pass a signal (for example `AbortSignal.timeout(ms)`) when the wait needs a bound.
#[bitwarden_ffi::wasm_export(js_name = autotypeRequestSetEnabled)]
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
///
/// There is no built-in timeout: the request waits until main responds or `abort_signal` aborts,
/// so pass a signal (for example `AbortSignal.timeout(ms)`) when the wait needs a bound.
#[bitwarden_ffi::wasm_export(js_name = autotypeRequestSetKeyboardShortcut)]
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

/// Asks the desktop main process which applications are currently running.
///
/// An empty list could mean there are no apps running, or that the apps running
/// didn't have the matching data needed for use with Autotype.
///
/// There is no built-in timeout: the request waits until main responds or `abort_signal` aborts,
/// so pass a signal (for example `AbortSignal.timeout(ms)`) when the wait needs a bound.
#[bitwarden_ffi::wasm_export(js_name = autotypeRequestListRunningApps)]
pub async fn autotype_request_list_running_apps(
    ipc_client: &JsIpcClient,
    abort_signal: Option<AbortSignal>,
) -> Result<AutotypeListRunningAppsResponse, RequestError> {
    ipc_client
        .client
        .request(
            AutotypeListRunningAppsRequest,
            Endpoint::DesktopMain,
            abort_signal.map(|signal| signal.to_cancellation_token()),
        )
        .await
}
