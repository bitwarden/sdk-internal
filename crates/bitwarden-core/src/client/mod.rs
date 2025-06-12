//! Bitwarden SDK Client

#[allow(clippy::module_inception)]
mod client;
#[allow(missing_docs)]
pub mod client_settings;
#[allow(missing_docs)]
pub mod encryption_settings;
#[allow(missing_docs)]
pub mod internal;
pub use internal::ApiConfigurations;
#[allow(missing_docs)]
pub mod login_method;
#[cfg(feature = "secrets")]
pub(crate) use login_method::ServiceAccountLoginMethod;
pub(crate) use login_method::{LoginMethod, UserLoginMethod};
#[cfg(feature = "internal")]
mod flags;

pub use client::Client;
pub use client_settings::{ClientSettings, DeviceType};

#[allow(missing_docs)]
#[cfg(feature = "internal")]
pub mod test_accounts;
