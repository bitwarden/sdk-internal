//! Bitwarden SDK Client

mod builder;
#[allow(clippy::module_inception)]
mod client;
#[allow(missing_docs)]
pub mod client_settings;
#[allow(missing_docs)]
pub mod encryption_settings;
mod from_client_part;
#[allow(missing_docs)]
pub mod internal;
pub use from_client_part::{FromClient, FromClientPart};
pub use internal::ApiConfigurations;
#[allow(missing_docs)]
pub mod login_method;
#[cfg(any(feature = "internal", feature = "secrets"))]
pub(crate) use login_method::LoginMethod;
#[cfg(feature = "secrets")]
pub(crate) use login_method::ServiceAccountLoginMethod;
pub(crate) use login_method::UserLoginMethod;
#[cfg(feature = "internal")]
mod flags;
#[cfg(feature = "internal")]
pub mod persisted_state;

pub mod tracing_middleware;

pub use builder::ClientBuilder;
pub(crate) use builder::{build_default_headers, new_http_client_builder};
pub use client::Client;
pub use client_settings::{
    ClientName, ClientSettings, DeviceType, HostPlatformInfo, get_host_platform_info,
    init_host_platform_info,
};

#[allow(missing_docs)]
#[cfg(feature = "internal")]
pub mod test_accounts;
