/*
 * Bitwarden Internal API
 *
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: latest
 *
 * Generated by: https://openapi-generator.tech
 */

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::models;
///
#[repr(i64)]
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize_repr, Deserialize_repr,
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

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Android => "0",
                Self::iOS => "1",
                Self::ChromeExtension => "2",
                Self::FirefoxExtension => "3",
                Self::OperaExtension => "4",
                Self::EdgeExtension => "5",
                Self::WindowsDesktop => "6",
                Self::MacOsDesktop => "7",
                Self::LinuxDesktop => "8",
                Self::ChromeBrowser => "9",
                Self::FirefoxBrowser => "10",
                Self::OperaBrowser => "11",
                Self::EdgeBrowser => "12",
                Self::IEBrowser => "13",
                Self::UnknownBrowser => "14",
                Self::AndroidAmazon => "15",
                Self::UWP => "16",
                Self::SafariBrowser => "17",
                Self::VivaldiBrowser => "18",
                Self::VivaldiExtension => "19",
                Self::SafariExtension => "20",
                Self::SDK => "21",
                Self::Server => "22",
                Self::WindowsCLI => "23",
                Self::MacOsCLI => "24",
                Self::LinuxCLI => "25",
                Self::DuckDuckGoBrowser => "26",
            }
        )
    }
}
impl Default for DeviceType {
    fn default() -> DeviceType {
        Self::Android
    }
}
