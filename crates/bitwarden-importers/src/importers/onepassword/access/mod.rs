//! Read access to a 1Password account: log in with the master password and Secret Key, then
//! download and decrypt every accessible vault into a native 1Password model.
//!
//! A port of the OnePassword module in Bitwarden's C# `password-manager-access` library. See
//! `README.md` for the porting notes and open questions.

mod account_key;
mod client;
pub use client::Client;
mod credentials;
pub use credentials::Credentials;
mod device;
pub use device::generate_device_uuid;
mod error;
pub use error::OnePasswordError;
mod identity;
mod kdf;
mod keychain;
mod login;
mod mac;
pub mod model;
mod opdata;
mod rest;
mod rsa;
mod session;
mod sign_in;
pub use sign_in::{SignInAddress, SignInDomain};
mod srp;
mod two_factor;
pub use two_factor::{TotpResult, TwoFactorUi};
// The DTO fields are named after the JSON keys they carry; documenting each one adds nothing.
#[allow(missing_docs)]
pub mod wire;
