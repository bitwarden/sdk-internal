use std::fmt;

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
/// };
/// let default = ClientSettings::default();
/// ```
#[derive(Serialize, Deserialize, Debug, JsonSchema)]
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
    /// Bitwarden Client Version to send to Bitwarden.
    pub bitwarden_client_version: Option<String>,
}

impl Default for ClientSettings {
    fn default() -> Self {
        Self {
            identity_url: "https://identity.bitwarden.com".into(),
            api_url: "https://api.bitwarden.com".into(),
            user_agent: "Bitwarden Rust-SDK".into(),
            device_type: DeviceType::SDK,
            bitwarden_client_version: None,
        }
    }
}

#[expect(non_camel_case_types, missing_docs)]
#[derive(Serialize, Deserialize, Copy, Clone, Debug, JsonSchema)]
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
pub(crate) enum ClientName {
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
