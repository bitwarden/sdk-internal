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
#[cfg(feature = "cli")]
pub use internal::PersistedAuthState;
#[allow(missing_docs)]
pub mod login_method;
pub(crate) use login_method::LoginMethod;
#[cfg(feature = "secrets")]
pub(crate) use login_method::ServiceAccountLoginMethod;
// Export publicly for CLI persistence
pub use login_method::UserLoginMethod;
#[cfg(feature = "internal")]
mod flags;

pub use client::Client;
pub use client_settings::{ClientName, ClientSettings, DeviceType};

#[allow(missing_docs)]
#[cfg(feature = "internal")]
pub mod test_accounts;
