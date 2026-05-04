use std::{fmt, sync::OnceLock};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Basic client behavior settings. These settings specify the various targets and behavior of the
/// Bitwarden Client. They are optional and uneditable once the client is initialized.
///
/// Defaults to
///
/// ```
/// # use bitwarden_core::{ClientSettings, DeviceType};
/// let settings = ClientSettings {
///     identity_url: "https://identity.bitwarden.com".to_string(),
///     api_url: "https://api.bitwarden.com".to_string(),
///     user_agent: "Bitwarden Rust-SDK".to_string(),
///     device_type: DeviceType::SDK,
///     bitwarden_client_version: None,
///     bitwarden_package_type: None,
///     device_identifier: None,
/// };
/// let default = ClientSettings::default();
/// ```
#[derive(Serialize, Deserialize, Debug, JsonSchema, Clone)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct ClientSettings {
    /// The identity url of the targeted Bitwarden instance. Defaults to `https://identity.bitwarden.com`
    pub identity_url: String,
    /// The api url of the targeted Bitwarden instance. Defaults to `https://api.bitwarden.com`
    pub api_url: String,
    /// The user_agent to sent to Bitwarden. Defaults to `Bitwarden Rust-SDK`
    pub user_agent: String,
    /// Device type to send to Bitwarden. Defaults to SDK
    pub device_type: DeviceType,

    // TODO: PM-29939 - Remove optionality when all clients pass these values
    /// Device identifier to send to Bitwarden. Optional for now in transition period.
    pub device_identifier: Option<String>,
    /// Bitwarden Client Version to send to Bitwarden. Optional for now in transition period.
    pub bitwarden_client_version: Option<String>,
    /// Bitwarden Package Type to send to Bitwarden. We should evaluate this field to see if it
    /// should be optional later.
    pub bitwarden_package_type: Option<String>,
}

impl Default for ClientSettings {
    fn default() -> Self {
        Self {
            identity_url: "https://identity.bitwarden.com".into(),
            api_url: "https://api.bitwarden.com".into(),
            user_agent: "Bitwarden Rust-SDK".into(),
            device_type: DeviceType::SDK,
            device_identifier: None,
            bitwarden_client_version: None,
            bitwarden_package_type: None,
        }
    }
}

#[allow(non_camel_case_types, missing_docs)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, JsonSchema, PartialEq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub enum DeviceType {
    Android = 0,
    iOS = 1,
    ChromeExtension = 2,
    FirefoxExtension = 3,
    OperaExtension = 4,
    EdgeExtension = 5,
    WindowsDesktop = 6,
    MacOsDesktop = 7,
    LinuxDesktop = 8,
    ChromeBrowser = 9,
    FirefoxBrowser = 10,
    OperaBrowser = 11,
    EdgeBrowser = 12,
    IEBrowser = 13,
    UnknownBrowser = 14,
    AndroidAmazon = 15,
    UWP = 16,
    SafariBrowser = 17,
    VivaldiBrowser = 18,
    VivaldiExtension = 19,
    SafariExtension = 20,
    SDK = 21,
    Server = 22,
    WindowsCLI = 23,
    MacOsCLI = 24,
    LinuxCLI = 25,
    DuckDuckGoBrowser = 26,
}

#[derive(Copy, Clone, Debug)]
pub enum ClientName {
    Web,
    Browser,
    Desktop,
    Mobile,
    Cli,
}

impl From<DeviceType> for Option<ClientName> {
    fn from(device_type: DeviceType) -> Self {
        match device_type {
            DeviceType::Android | DeviceType::AndroidAmazon | DeviceType::iOS => {
                Some(ClientName::Mobile)
            }

            DeviceType::ChromeBrowser
            | DeviceType::FirefoxBrowser
            | DeviceType::OperaBrowser
            | DeviceType::EdgeBrowser
            | DeviceType::IEBrowser
            | DeviceType::SafariBrowser
            | DeviceType::VivaldiBrowser
            | DeviceType::DuckDuckGoBrowser
            | DeviceType::UnknownBrowser => Some(ClientName::Web),

            DeviceType::ChromeExtension
            | DeviceType::FirefoxExtension
            | DeviceType::OperaExtension
            | DeviceType::EdgeExtension
            | DeviceType::VivaldiExtension
            | DeviceType::SafariExtension => Some(ClientName::Browser),

            DeviceType::LinuxDesktop
            | DeviceType::MacOsDesktop
            | DeviceType::WindowsDesktop
            | DeviceType::UWP => Some(ClientName::Desktop),

            DeviceType::WindowsCLI | DeviceType::MacOsCLI | DeviceType::LinuxCLI => {
                Some(ClientName::Cli)
            }

            DeviceType::SDK | DeviceType::Server => None,
        }
    }
}

impl fmt::Display for ClientName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ClientName::Web => "web",
            ClientName::Browser => "browser",
            ClientName::Desktop => "desktop",
            ClientName::Mobile => "mobile",
            ClientName::Cli => "cli",
        };
        write!(f, "{}", s)
    }
}

/// Process-wide, application-provided platform information.
///
/// Initialize exactly once at application startup via [`init_host_platform_info`];
/// read via [`get_host_platform_info`]. Subsequent `init` calls are ignored.
#[derive(Debug, Clone)]
pub struct HostPlatformInfo {
    pub user_agent: String,
    pub device_type: DeviceType,
    pub device_identifier: Option<String>,
    pub bitwarden_client_version: Option<String>,
    pub bitwarden_package_type: Option<String>,
}

static HOST_PLATFORM_INFO: OnceLock<HostPlatformInfo> = OnceLock::new();

/// Initialize the global [`HostPlatformInfo`].
///
/// Should be called once during application startup, before any
/// `Client::load_from_state` calls. Subsequent calls are silently ignored.
pub fn init_host_platform_info(info: HostPlatformInfo) {
    let _ = HOST_PLATFORM_INFO.set(info);
}

/// Returns the globally-initialized [`HostPlatformInfo`].
///
/// # Panics
/// Panics if [`init_host_platform_info`] has not yet been called.
pub fn get_host_platform_info() -> &'static HostPlatformInfo {
    HOST_PLATFORM_INFO
        .get()
        .expect("host platform info to be initialized")
}

#[cfg(test)]
mod tests {
    use super::*;

    // `OnceLock` is process-global, so a single sequential test covers the
    // not-set, happy-path, and already-set cases without cross-test leakage.
    #[test]
    fn init_then_get_preserves_first_value() {
        // Not-set case: `get` must panic before any `init` call.
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let not_set = std::panic::catch_unwind(get_host_platform_info);
        std::panic::set_hook(prev_hook);
        assert!(not_set.is_err(), "expected panic before init");

        let first = HostPlatformInfo {
            user_agent: "first".into(),
            device_type: DeviceType::SDK,
            device_identifier: Some("dev-1".into()),
            bitwarden_client_version: Some("1.0.0".into()),
            bitwarden_package_type: Some("test".into()),
        };
        init_host_platform_info(first.clone());

        let got = get_host_platform_info();
        assert_eq!(got.user_agent, first.user_agent);
        assert_eq!(got.device_type, first.device_type);
        assert_eq!(got.device_identifier, first.device_identifier);

        let second = HostPlatformInfo {
            user_agent: "second".into(),
            ..first.clone()
        };
        init_host_platform_info(second);

        let after = get_host_platform_info();
        assert_eq!(after.user_agent, first.user_agent);
    }
}
