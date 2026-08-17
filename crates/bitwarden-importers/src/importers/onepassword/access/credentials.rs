//! The credentials a password login needs.

use zeroize::Zeroize;

use super::sign_in::SignInAddress;

/// The credentials for a password + Secret Key login.
///
/// Deliberately not `Debug`: it holds the master password and Secret Key.
#[derive(Clone)]
pub struct Credentials {
    /// The account's email address.
    pub username: String,
    /// The account's master password.
    pub password: String,
    /// The account's Secret Key (Account Key), such as `A3-XXXXXX-...`.
    pub account_key: String,
    /// Where the account signs in, such as `my.1password.com`.
    pub sign_in_address: SignInAddress,
    /// The device id for this import. See `device::generate_device_uuid`.
    pub device_uuid: String,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.password.zeroize();
        self.account_key.zeroize();
    }
}
