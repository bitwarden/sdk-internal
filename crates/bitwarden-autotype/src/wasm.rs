//! WASM bindings for the autotype IPC requests, exposed to the clients through
//! `@bitwarden/sdk-internal`.
//!
//! There is one driver interface per desktop process, each implemented by the user of this
//! crate (for example, within the Bitwarden desktop app):
//! - `AutotypeDriver` handles requests in the main process, registered with
//!   `registerAutotypeHandlers`.
//! - `AutotypeRenderDriver` handles requests in the render process, registered with
//!   `registerAutotypeRenderHandlers`.

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
/// The AutotypeDriver and AutotypeRenderDriver interfaces are TS interfaces that will be
/// implemented by the user of this crate (e.g. in the Bitwarden desktop app).
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

/**
 * Applies Autotype requests in the desktop render process.
 *
 * Implement each method as an `async` function. A method that throws synchronously or returns
 * a non-Promise value leaves the request without a response.
 */
export interface AutotypeRenderDriver {
    /**
     * Find the credentials to autotype into the focused app, as requested
     * by the main process when the user presses the autotype shortcut.
     * Returns the matching vault item's username and password, or
     * `undefined` if nothing matches.
     */
    get_autotype_credentials(app: AutotypeRunningApp): Promise<AutotypeCredentials | undefined>;
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

    /// JavaScript implementation of the Autotype operations applied in the render process.
    #[wasm_bindgen(js_name = AutotypeRenderDriver, typescript_type = "AutotypeRenderDriver")]
    pub type RawJsAutotypeRenderDriver;

    /// Find the credentials to autotype into the focused app, as requested by the main process.
    /// The driver returns an `AutotypeCredentials` or `undefined`, received here as a raw
    /// `JsValue` so `JsAutotypeRenderDriver::get_autotype_credentials` can reject malformed
    /// credentials.
    #[wasm_bindgen(method, catch)]
    async fn get_autotype_credentials(
        this: &RawJsAutotypeRenderDriver,
        app: AutotypeRunningApp,
    ) -> Result<JsValue, JsValue>;
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

/// The credentials the render process found for an [`AutotypeGetCredentialsRequest`].
///
/// `Debug` is implemented by hand so the username and password never reach logs.
#[derive(Clone, Serialize, Deserialize)]
#[bitwarden_ffi::wasm_record]
pub struct AutotypeCredentials {
    /// The matching vault item's username.
    pub username: String,
    /// The matching vault item's password.
    pub password: String,
}

impl std::fmt::Debug for AutotypeCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutotypeCredentials")
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .finish()
    }
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

/// Wraps the JavaScript render driver in a [`ThreadBoundRunner`] so it can be used from the
/// `Send` futures an [`RpcHandler`] is required to return.
struct JsAutotypeRenderDriver {
    runner: ThreadBoundRunner<RawJsAutotypeRenderDriver>,
}

impl JsAutotypeRenderDriver {
    fn new(runner: ThreadBoundRunner<RawJsAutotypeRenderDriver>) -> Self {
        Self { runner }
    }

    /// Finds the credentials to autotype into the focused app, as requested by the main process.
    /// Returns `None` if nothing matches, or if the driver fails or returns malformed credentials.
    async fn get_autotype_credentials(
        &self,
        app: AutotypeRunningApp,
    ) -> Option<AutotypeCredentials> {
        self.runner
            .run_in_thread(move |driver| async move {
                let value = match driver.get_autotype_credentials(app).await {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::error!(
                            ?error,
                            "Autotype render driver failed to get autotype credentials"
                        );
                        return None;
                    }
                };

                // `undefined` (or `null`) is the normal reply when no vault item matches.
                if value.is_undefined() || value.is_null() {
                    return None;
                }

                // The deserialization error isn't logged, because it can quote the value it
                // failed on, which may hold the credentials.
                match serde_wasm_bindgen::from_value(value) {
                    Ok(credentials) => Some(credentials),
                    Err(_) => {
                        tracing::warn!("Autotype render driver returned malformed credentials");
                        None
                    }
                }
            })
            .await
            .unwrap_or_else(|error| {
                tracing::error!(
                    ?error,
                    "Autotype render runner failed to get autotype credentials"
                );
                None
            })
    }
}

/// Determines if a request came from the `expected` source.
///
/// A rejection is logged with the request's
/// [`RpcRequest::NAME`], the source it came from, and the source that was expected.
fn from_source(info: &RpcRequestInfo, expected: Source, request: &str) -> bool {
    let allowed = info.source == expected;

    if !allowed {
        tracing::warn!(
            request,
            source = ?info.source,
            ?expected,
            "Autotype rejected a request from an unexpected source"
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
/// `success: false` before the driver is called. See [`from_source`].
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
        if !from_source(&info, Source::DesktopRenderer, Self::Request::NAME) {
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
/// `success: false` before the shortcut reaches the driver. See [`from_source`].
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
        if !from_source(&info, Source::DesktopRenderer, Self::Request::NAME) {
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
/// without the driver being asked to enumerate anything. See [`from_source`].
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
        if !from_source(&info, Source::DesktopRenderer, Self::Request::NAME) {
            return AutotypeListRunningAppsResponse { apps: Vec::new() };
        }

        AutotypeListRunningAppsResponse {
            apps: self.driver.list_running_apps().await,
        }
    }
}

/// A request from the main process, sent when the user presses the Autotype shortcut, asking the
/// render process for the credentials to autotype into the focused app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutotypeGetCredentialsRequest {
    /// The focused app.
    pub app: AutotypeRunningApp,
}

/// A response to an [`AutotypeGetCredentialsRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[bitwarden_ffi::wasm_record]
pub struct AutotypeGetCredentialsResponse {
    /// The matching credentials, or `None` if no vault item matched.
    #[tsify(optional)]
    pub credentials: Option<AutotypeCredentials>,
}

impl RpcRequest for AutotypeGetCredentialsRequest {
    type Response = AutotypeGetCredentialsResponse;

    const NAME: &str = "AutotypeGetCredentialsRequest";
}

/// An [`RpcHandler`] that finds the credentials to autotype through a
/// [`RawJsAutotypeRenderDriver`].
///
/// Only requests from the desktop main process are answered; any other source (including
/// native-messaging peers that main forwards to the render process) gets no match without the
/// driver being called, so it can't request credentials. See [`from_source`].
struct AutotypeGetCredentialsHandler {
    driver: JsAutotypeRenderDriver,
}

impl AutotypeGetCredentialsHandler {
    fn new(driver: JsAutotypeRenderDriver) -> Self {
        Self { driver }
    }
}

impl RpcHandler for AutotypeGetCredentialsHandler {
    type Request = AutotypeGetCredentialsRequest;

    async fn handle(
        &self,
        request: Self::Request,
        info: RpcRequestInfo,
    ) -> AutotypeGetCredentialsResponse {
        if !from_source(&info, Source::DesktopMain, Self::Request::NAME) {
            return AutotypeGetCredentialsResponse { credentials: None };
        }

        AutotypeGetCredentialsResponse {
            credentials: self.driver.get_autotype_credentials(request.app).await,
        }
    }
}

/// This registers the Autotype handlers so the client responds to Autotype requests through
/// the `RawJsAutotypeDriver`. Call this on the desktop main process's IPC client.
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

/// This registers the Autotype handlers so the client responds to Autotype requests from the
/// main process through the `RawJsAutotypeRenderDriver`. Call this on the desktop render
/// process's IPC client.
#[bitwarden_ffi::wasm_export(js_name = registerAutotypeRenderHandlers)]
pub async fn register_autotype_render_handlers(
    ipc_client: &JsIpcClient,
    driver: RawJsAutotypeRenderDriver,
) {
    let runner = ThreadBoundRunner::new(driver);

    ipc_client
        .client
        .register_rpc_handler(AutotypeGetCredentialsHandler::new(
            JsAutotypeRenderDriver::new(runner),
        ))
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

/// Sends an `AutotypeGetCredentialsRequest` to the desktop render process, asking for the
/// credentials to autotype into the focused app. The response's `credentials` is empty when no
/// vault item matches.
///
/// The response doesn't identify the app it's for. Keep the focused app's identity from before
/// sending the request, and confirm that app is still focused before typing. If it isn't, the user
/// has switched apps, and nothing should be typed.
///
/// The render process must have called `registerAutotypeRenderHandlers` first. Otherwise the
/// request fails (for example, with a "no handler found" error) or waits until `abort_signal`
/// fires.
///
/// There is no built-in timeout, so always pass `abort_signal` (for example
/// `AbortSignal.timeout(ms)`). Without one, the request never completes if the render process
/// doesn't respond.
#[bitwarden_ffi::wasm_export(js_name = autotypeRequestGetCredentials)]
pub async fn autotype_request_get_credentials(
    ipc_client: &JsIpcClient,
    app: AutotypeRunningApp,
    abort_signal: Option<AbortSignal>,
) -> Result<AutotypeGetCredentialsResponse, RequestError> {
    ipc_client
        .client
        .request(
            AutotypeGetCredentialsRequest { app },
            Endpoint::DesktopRenderer,
            abort_signal.map(|signal| signal.to_cancellation_token()),
        )
        .await
}
