//! WASM bindings for the autotype IPC requests, exposed to the clients through
//! `@bitwarden/sdk-internal`.
//!
//! There is one driver interface per desktop process, each implemented by the user of this
//! crate (for example, within the Bitwarden desktop app):
//! - `AutotypeMainDriver` handles requests in the main process, registered with
//!   `registerAutotypeMainHandlers`.
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
/// The AutotypeMainDriver and AutotypeRenderDriver interfaces are TS interfaces that will be
/// implemented by the user of this crate (e.g. in the Bitwarden desktop app).
const TS_AUTOTYPE_TYPES: &'static str = r#"
/**
 * Applies Autotype requests in the desktop main process.
 *
 * Implement each method as an `async` function. A method that throws synchronously or returns
 * a non-Promise value leaves the request without a response.
 */
export interface AutotypeMainDriver {
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

    /**
     * Set whether the Autotype confirmation dialog should be shown, as
     * requested by the render process. Returns a boolean representing if
     * changing the setting was successful or not.
     *
     * The render process owns this setting.
     */
    set_autotype_confirmation_enabled(enabled: boolean): Promise<boolean>;
}

/**
 * Applies Autotype requests in the desktop render process.
 *
 * Implement each method as an `async` function. A method that throws synchronously or returns
 * a non-Promise value leaves the request without a response.
 */
export interface AutotypeRenderDriver {
    /**
     * Set whether the Autotype confirmation dialog should be shown, as
     * requested by the main process. Returns a boolean representing if
     * changing the setting was successful or not.
     *
     * The render process owns this setting.
     */
    set_autotype_confirmation_enabled(enabled: boolean): Promise<boolean>;

    /**
     * Find the credentials to autotype into the focused app, as requested
     * by the main process when the user presses the autotype shortcut.
     * Returns the matching vault item's username and password with the
     * `metadata` it was given, or `undefined` if nothing matches.
     */
    execute_autotype(app: AutotypeRunningApp, metadata: AppMetadata): Promise<AutotypeExecuteMatch | undefined>;
}
"#;

#[bitwarden_ffi::wasm_import]
extern "C" {
    /// JavaScript implementation of the various Autotype operations.
    #[wasm_bindgen(js_name = AutotypeMainDriver, typescript_type = "AutotypeMainDriver")]
    pub type RawJsAutotypeMainDriver;

    /// Enable or disable autotype. Returns if setting the enabled state was successful or not.
    #[wasm_bindgen(method, catch)]
    async fn set_autotype_enabled(
        this: &RawJsAutotypeMainDriver,
        enabled: bool,
    ) -> Result<JsValue, JsValue>;

    /// Set the autotype keyboard shortcut. Returns a boolean
    /// representing if setting the shortcut was successful or not.
    #[wasm_bindgen(method, catch)]
    async fn set_autotype_keyboard_shortcut(
        this: &RawJsAutotypeMainDriver,
        shortcut: Vec<String>,
    ) -> Result<JsValue, JsValue>;

    /// List the applications currently running. The driver returns an `AutotypeRunningApp[]`,
    /// received here as a raw `JsValue` so `JsAutotypeMainDriver::list_running_apps` can skip
    /// entries that don't match `AutotypeRunningApp`.
    #[wasm_bindgen(method, catch)]
    async fn list_running_apps(this: &RawJsAutotypeMainDriver) -> Result<JsValue, JsValue>;

    /// Set whether the Autotype confirmation dialog should be shown, as requested by the render
    /// process. Returns a boolean representing if changing the setting was successful or not.
    #[wasm_bindgen(method, catch)]
    async fn set_autotype_confirmation_enabled(
        this: &RawJsAutotypeMainDriver,
        enabled: bool,
    ) -> Result<JsValue, JsValue>;

    /// JavaScript implementation of the Autotype operations applied in the render process.
    #[wasm_bindgen(js_name = AutotypeRenderDriver, typescript_type = "AutotypeRenderDriver")]
    pub type RawJsAutotypeRenderDriver;

    /// Set whether the Autotype confirmation dialog should be shown, as requested by the main
    /// process. Returns a boolean representing if changing the setting was successful or not.
    #[wasm_bindgen(method, catch)]
    async fn set_autotype_confirmation_enabled(
        this: &RawJsAutotypeRenderDriver,
        enabled: bool,
    ) -> Result<JsValue, JsValue>;

    /// Find the credentials to autotype into the focused app, as requested by the main process.
    /// The driver returns an `AutotypeExecuteMatch` or `undefined`, received here as a raw
    /// `JsValue` so `JsAutotypeRenderDriver::execute_autotype` can reject a malformed match.
    #[wasm_bindgen(method, catch)]
    async fn execute_autotype(
        this: &RawJsAutotypeRenderDriver,
        app: AutotypeRunningApp,
        metadata: AppMetadata,
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

/// Identifies the app Autotype was triggered for, so main can confirm the focused app hasn't
/// changed before typing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[bitwarden_ffi::wasm_record]
pub struct AppMetadata {
    /// The app's unique ID.
    pub id: u32,
    /// The app's process ID.
    pub pid: u32,
}

/// The credentials the render process found for an [`AutotypeExecuteRequest`].
///
/// `Debug` is implemented by hand so the username and password never reach logs.
#[derive(Clone, Serialize, Deserialize)]
#[bitwarden_ffi::wasm_record]
pub struct AutotypeExecuteMatch {
    /// The [`AppMetadata`] from the request, so main can confirm the focused app hasn't changed.
    pub metadata: AppMetadata,
    /// The matching vault item's username.
    pub username: String,
    /// The matching vault item's password.
    pub password: String,
}

impl std::fmt::Debug for AutotypeExecuteMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutotypeExecuteMatch")
            .field("metadata", &self.metadata)
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Wraps the JavaScript driver in a [`ThreadBoundRunner`] so it can be used from the `Send`
/// futures an [`RpcHandler`] is required to return.
struct JsAutotypeMainDriver {
    runner: ThreadBoundRunner<RawJsAutotypeMainDriver>,
}

impl JsAutotypeMainDriver {
    fn new(runner: ThreadBoundRunner<RawJsAutotypeMainDriver>) -> Self {
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

    /// Sets whether the Autotype confirmation dialog should be shown, as requested by the render
    /// process. Returns if changing the setting was successful or not.
    async fn set_autotype_confirmation_enabled(&self, enabled: bool) -> bool {
        self.runner
            .run_in_thread(move |driver| async move {
                match driver.set_autotype_confirmation_enabled(enabled).await {
                    Ok(value) => value.as_bool().unwrap_or_else(|| {
                        tracing::error!(
                            "Autotype driver returned a non-boolean set-confirmation-enabled result"
                        );
                        false
                    }),
                    Err(error) => {
                        tracing::error!(
                            ?error,
                            "Autotype driver failed to set the confirmation enabled state"
                        );
                        false
                    }
                }
            })
            .await
            .unwrap_or_else(|error| {
                tracing::error!(
                    ?error,
                    "Autotype runner failed to set the confirmation enabled state"
                );
                false
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

    /// Sets whether the Autotype confirmation dialog should be shown, as requested by the main
    /// process. Returns if changing the setting was successful or not.
    async fn set_autotype_confirmation_enabled(&self, enabled: bool) -> bool {
        self.runner
            .run_in_thread(move |driver| async move {
                match driver.set_autotype_confirmation_enabled(enabled).await {
                    Ok(value) => value.as_bool().unwrap_or_else(|| {
                        tracing::error!(
                            "Autotype render driver returned a non-boolean \
                             set-confirmation-enabled result"
                        );
                        false
                    }),
                    Err(error) => {
                        tracing::error!(
                            ?error,
                            "Autotype render driver failed to set the confirmation enabled state"
                        );
                        false
                    }
                }
            })
            .await
            .unwrap_or_else(|error| {
                tracing::error!(
                    ?error,
                    "Autotype render runner failed to set the confirmation enabled state"
                );
                false
            })
    }

    /// Finds the credentials to autotype into the focused app, as requested by the main process.
    /// Returns `None` if nothing matches, or if the driver fails or returns a malformed match.
    async fn execute_autotype(
        &self,
        app: AutotypeRunningApp,
        metadata: AppMetadata,
    ) -> Option<AutotypeExecuteMatch> {
        self.runner
            .run_in_thread(move |driver| async move {
                let value = match driver.execute_autotype(app, metadata).await {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::error!(
                            ?error,
                            "Autotype render driver failed to execute autotype"
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
                    Ok(matched) => Some(matched),
                    Err(_) => {
                        tracing::warn!("Autotype render driver returned a malformed match");
                        None
                    }
                }
            })
            .await
            .unwrap_or_else(|error| {
                tracing::error!(?error, "Autotype render runner failed to execute autotype");
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

/// An [`RpcHandler`] that applies the requested state through a [`RawJsAutotypeMainDriver`].
///
/// Only requests from the desktop render process are applied; any other source is refused with
/// `success: false` before the driver is called. See [`from_source`].
struct AutotypeSetEnabledHandler {
    driver: JsAutotypeMainDriver,
}

impl AutotypeSetEnabledHandler {
    fn new(driver: JsAutotypeMainDriver) -> Self {
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

/// An [`RpcHandler`] that applies the requested shortcut through a [`RawJsAutotypeMainDriver`].
///
/// Only requests from the desktop render process are applied; any other source is refused with
/// `success: false` before the shortcut reaches the driver. See [`from_source`].
struct AutotypeSetKeyboardShortcutHandler {
    driver: JsAutotypeMainDriver,
}

impl AutotypeSetKeyboardShortcutHandler {
    fn new(driver: JsAutotypeMainDriver) -> Self {
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

/// An [`RpcHandler`] that lists running applications through a [`RawJsAutotypeMainDriver`].
///
/// Only requests from the desktop render process are answered; any other source gets an empty list
/// without the driver being asked to enumerate anything. See [`from_source`].
struct AutotypeListRunningAppsHandler {
    driver: JsAutotypeMainDriver,
}

impl AutotypeListRunningAppsHandler {
    fn new(driver: JsAutotypeMainDriver) -> Self {
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

/// A request from the render process asking the main process to change whether the Autotype
/// confirmation dialog should be shown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutotypeSetConfirmationEnabledFromRenderRequest {
    /// Whether the Autotype confirmation dialog should be shown.
    pub enabled: bool,
}

/// A response to an [`AutotypeSetConfirmationEnabledFromRenderRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[bitwarden_ffi::wasm_record]
pub struct AutotypeSetConfirmationEnabledFromRenderResponse {
    /// Whether the requested change to the confirmation dialog setting was applied.
    pub success: bool,
}

impl RpcRequest for AutotypeSetConfirmationEnabledFromRenderRequest {
    type Response = AutotypeSetConfirmationEnabledFromRenderResponse;

    const NAME: &str = "AutotypeSetConfirmationEnabledFromRenderRequest";
}

/// An [`RpcHandler`] that applies the requested confirmation dialog setting through a
/// [`RawJsAutotypeMainDriver`].
///
/// Only requests from the desktop render process are applied; any other source is refused with
/// `success: false` before the driver is called. See [`from_source`].
struct AutotypeSetConfirmationEnabledFromRenderHandler {
    driver: JsAutotypeMainDriver,
}

impl AutotypeSetConfirmationEnabledFromRenderHandler {
    fn new(driver: JsAutotypeMainDriver) -> Self {
        Self { driver }
    }
}

impl RpcHandler for AutotypeSetConfirmationEnabledFromRenderHandler {
    type Request = AutotypeSetConfirmationEnabledFromRenderRequest;

    async fn handle(
        &self,
        request: Self::Request,
        info: RpcRequestInfo,
    ) -> AutotypeSetConfirmationEnabledFromRenderResponse {
        if !from_source(&info, Source::DesktopRenderer, Self::Request::NAME) {
            return AutotypeSetConfirmationEnabledFromRenderResponse { success: false };
        }

        AutotypeSetConfirmationEnabledFromRenderResponse {
            success: self
                .driver
                .set_autotype_confirmation_enabled(request.enabled)
                .await,
        }
    }
}

/// A request from the main process asking the render process to change whether the Autotype
/// confirmation dialog should be shown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutotypeSetConfirmationEnabledFromMainRequest {
    /// Whether the Autotype confirmation dialog should be shown.
    pub enabled: bool,
}

/// A response to an [`AutotypeSetConfirmationEnabledFromMainRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[bitwarden_ffi::wasm_record]
pub struct AutotypeSetConfirmationEnabledFromMainResponse {
    /// Whether the requested change to the confirmation dialog setting was applied.
    pub success: bool,
}

impl RpcRequest for AutotypeSetConfirmationEnabledFromMainRequest {
    type Response = AutotypeSetConfirmationEnabledFromMainResponse;

    const NAME: &str = "AutotypeSetConfirmationEnabledFromMainRequest";
}

/// An [`RpcHandler`] that applies the requested confirmation dialog setting through a
/// [`RawJsAutotypeRenderDriver`].
///
/// Only requests from the desktop main process are applied; any other source (including
/// native-messaging peers that main forwards to the render process) is refused with
/// `success: false` before the driver is called. See [`from_source`].
struct AutotypeSetConfirmationEnabledFromMainHandler {
    driver: JsAutotypeRenderDriver,
}

impl AutotypeSetConfirmationEnabledFromMainHandler {
    fn new(driver: JsAutotypeRenderDriver) -> Self {
        Self { driver }
    }
}

impl RpcHandler for AutotypeSetConfirmationEnabledFromMainHandler {
    type Request = AutotypeSetConfirmationEnabledFromMainRequest;

    async fn handle(
        &self,
        request: Self::Request,
        info: RpcRequestInfo,
    ) -> AutotypeSetConfirmationEnabledFromMainResponse {
        if !from_source(&info, Source::DesktopMain, Self::Request::NAME) {
            return AutotypeSetConfirmationEnabledFromMainResponse { success: false };
        }

        AutotypeSetConfirmationEnabledFromMainResponse {
            success: self
                .driver
                .set_autotype_confirmation_enabled(request.enabled)
                .await,
        }
    }
}

/// A request from the main process, sent when the user presses the Autotype shortcut, asking the
/// render process for the credentials to autotype into the focused app.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutotypeExecuteRequest {
    /// The focused app.
    pub app: AutotypeRunningApp,
    /// The focused app's metadata, returned with a match so main can confirm the focused app
    /// hasn't changed.
    pub metadata: AppMetadata,
}

/// A response to an [`AutotypeExecuteRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[bitwarden_ffi::wasm_record]
pub struct AutotypeExecuteResponse {
    /// The matching credentials, or `None` if no vault item matched.
    #[tsify(optional)]
    pub matched: Option<AutotypeExecuteMatch>,
}

impl RpcRequest for AutotypeExecuteRequest {
    type Response = AutotypeExecuteResponse;

    const NAME: &str = "AutotypeExecuteRequest";
}

/// An [`RpcHandler`] that finds the credentials to autotype through a
/// [`RawJsAutotypeRenderDriver`].
///
/// Only requests from the desktop main process are answered; any other source (including
/// native-messaging peers that main forwards to the render process) gets no match without the
/// driver being called, so it can't request credentials. See [`from_source`].
struct AutotypeExecuteHandler {
    driver: JsAutotypeRenderDriver,
}

impl AutotypeExecuteHandler {
    fn new(driver: JsAutotypeRenderDriver) -> Self {
        Self { driver }
    }
}

impl RpcHandler for AutotypeExecuteHandler {
    type Request = AutotypeExecuteRequest;

    async fn handle(
        &self,
        request: Self::Request,
        info: RpcRequestInfo,
    ) -> AutotypeExecuteResponse {
        if !from_source(&info, Source::DesktopMain, Self::Request::NAME) {
            return AutotypeExecuteResponse { matched: None };
        }

        AutotypeExecuteResponse {
            matched: self
                .driver
                .execute_autotype(request.app, request.metadata)
                .await,
        }
    }
}

/// This registers the Autotype handlers so the client responds to Autotype requests through
/// the `RawJsAutotypeMainDriver`. Call this on the desktop main process's IPC client.
#[bitwarden_ffi::wasm_export(js_name = registerAutotypeMainHandlers)]
pub async fn register_autotype_main_handlers(
    ipc_client: &JsIpcClient,
    driver: RawJsAutotypeMainDriver,
) {
    let runner = ThreadBoundRunner::new(driver);

    ipc_client
        .client
        .register_rpc_handler(AutotypeSetEnabledHandler::new(JsAutotypeMainDriver::new(
            runner.clone(),
        )))
        .await;
    ipc_client
        .client
        .register_rpc_handler(AutotypeSetKeyboardShortcutHandler::new(
            JsAutotypeMainDriver::new(runner.clone()),
        ))
        .await;
    ipc_client
        .client
        .register_rpc_handler(AutotypeListRunningAppsHandler::new(
            JsAutotypeMainDriver::new(runner.clone()),
        ))
        .await;
    ipc_client
        .client
        .register_rpc_handler(AutotypeSetConfirmationEnabledFromRenderHandler::new(
            JsAutotypeMainDriver::new(runner),
        ))
        .await;
}

/// This registers the Autotype handlers so the client responds to Autotype requests from the
/// main process through the `RawJsAutotypeRenderDriver`. Call this on the desktop render
/// process's IPC client.
///
/// After registering, send the current confirmation setting to main with
/// `autotypeRequestSetConfirmationEnabledFromRender`, so main starts with the right value.
#[bitwarden_ffi::wasm_export(js_name = registerAutotypeRenderHandlers)]
pub async fn register_autotype_render_handlers(
    ipc_client: &JsIpcClient,
    driver: RawJsAutotypeRenderDriver,
) {
    let runner = ThreadBoundRunner::new(driver);

    ipc_client
        .client
        .register_rpc_handler(AutotypeSetConfirmationEnabledFromMainHandler::new(
            JsAutotypeRenderDriver::new(runner.clone()),
        ))
        .await;
    ipc_client
        .client
        .register_rpc_handler(AutotypeExecuteHandler::new(JsAutotypeRenderDriver::new(
            runner,
        )))
        .await;
}

/// Sends an `AutotypeSetEnabledRequest` to the desktop main process and reports whether the
/// requested change was successful.
///
/// There is no built-in timeout, so always pass `abort_signal` (for example
/// `AbortSignal.timeout(ms)`). Without one, the request never completes if main doesn't respond.
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
/// There is no built-in timeout, so always pass `abort_signal` (for example
/// `AbortSignal.timeout(ms)`). Without one, the request never completes if main doesn't respond.
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
/// There is no built-in timeout, so always pass `abort_signal` (for example
/// `AbortSignal.timeout(ms)`). Without one, the request never completes if main doesn't respond.
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

/// Sends an `AutotypeSetConfirmationEnabledFromRenderRequest` to the desktop main process and
/// reports whether the requested confirmation dialog setting was applied.
///
/// There is no built-in timeout, so always pass `abort_signal` (for example
/// `AbortSignal.timeout(ms)`). Without one, the request never completes if main doesn't respond.
#[bitwarden_ffi::wasm_export(js_name = autotypeRequestSetConfirmationEnabledFromRender)]
pub async fn autotype_request_set_confirmation_enabled_from_render(
    ipc_client: &JsIpcClient,
    enabled: bool,
    abort_signal: Option<AbortSignal>,
) -> Result<AutotypeSetConfirmationEnabledFromRenderResponse, RequestError> {
    ipc_client
        .client
        .request(
            AutotypeSetConfirmationEnabledFromRenderRequest { enabled },
            Endpoint::DesktopMain,
            abort_signal.map(|signal| signal.to_cancellation_token()),
        )
        .await
}

/// Sends an `AutotypeSetConfirmationEnabledFromMainRequest` to the desktop render process and
/// reports whether the requested confirmation dialog setting was applied.
///
/// The render process must have called `registerAutotypeRenderHandlers` first. Otherwise the
/// request fails (for example, with a "no handler found" error) or waits until `abort_signal`
/// fires.
///
/// There is no built-in timeout, so always pass `abort_signal` (for example
/// `AbortSignal.timeout(ms)`). Without one, the request never completes if the render process
/// doesn't respond.
#[bitwarden_ffi::wasm_export(js_name = autotypeRequestSetConfirmationEnabledFromMain)]
pub async fn autotype_request_set_confirmation_enabled_from_main(
    ipc_client: &JsIpcClient,
    enabled: bool,
    abort_signal: Option<AbortSignal>,
) -> Result<AutotypeSetConfirmationEnabledFromMainResponse, RequestError> {
    ipc_client
        .client
        .request(
            AutotypeSetConfirmationEnabledFromMainRequest { enabled },
            Endpoint::DesktopRenderer,
            abort_signal.map(|signal| signal.to_cancellation_token()),
        )
        .await
}

/// Sends an `AutotypeExecuteRequest` to the desktop render process, asking for the credentials to
/// autotype into the focused app. The response's `matched` is empty when no vault item matches.
///
/// Before typing, check that `matched.metadata` still matches the focused app. If it doesn't, the
/// user has switched apps, and nothing should be typed.
///
/// The render process must have called `registerAutotypeRenderHandlers` first. Otherwise the
/// request fails (for example, with a "no handler found" error) or waits until `abort_signal`
/// fires.
///
/// There is no built-in timeout, so always pass `abort_signal` (for example
/// `AbortSignal.timeout(ms)`). Without one, the request never completes if the render process
/// doesn't respond.
#[bitwarden_ffi::wasm_export(js_name = autotypeRequestExecute)]
pub async fn autotype_request_execute(
    ipc_client: &JsIpcClient,
    app: AutotypeRunningApp,
    metadata: AppMetadata,
    abort_signal: Option<AbortSignal>,
) -> Result<AutotypeExecuteResponse, RequestError> {
    ipc_client
        .client
        .request(
            AutotypeExecuteRequest { app, metadata },
            Endpoint::DesktopRenderer,
            abort_signal.map(|signal| signal.to_cancellation_token()),
        )
        .await
}
