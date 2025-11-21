//! Bitwarden SDK Client

#[expect(clippy::module_inception)]
mod client;
#[expect(missing_docs)]
pub mod client_settings;
#[expect(missing_docs)]
pub mod encryption_settings;
#[expect(missing_docs)]
pub mod internal;
pub use internal::ApiConfigurations;
#[expect(missing_docs)]
pub mod login_method;
#[cfg(feature = "secrets")]
pub(crate) use login_method::ServiceAccountLoginMethod;
pub(crate) use login_method::{LoginMethod, UserLoginMethod};
#[cfg(feature = "internal")]
mod flags;

pub use client::Client;
pub use client_settings::{ClientSettings, DeviceType};

#[expect(missing_docs)]
#[cfg(feature = "internal")]
pub mod test_accounts;
