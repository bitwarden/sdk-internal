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
#[cfg(feature = "secrets")]
pub(crate) use login_method::ServiceAccountLoginMethod;
#[cfg(any(feature = "internal", feature = "secrets"))]
pub(crate) use login_method::LoginMethod;
pub(crate) use login_method::UserLoginMethod;
#[cfg(feature = "internal")]
mod flags;
#[cfg(feature = "internal")]
pub mod persisted_state;

pub use builder::ClientBuilder;
pub use client::Client;
pub use client_settings::{ClientName, ClientSettings, DeviceType};

#[allow(missing_docs)]
#[cfg(feature = "internal")]
pub mod test_accounts;
