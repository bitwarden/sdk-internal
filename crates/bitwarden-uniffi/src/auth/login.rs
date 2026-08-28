use bitwarden_auth::login::{
    login_via_password::{PasswordLoginRequest, PasswordPreloginResponse},
    models::LoginResponse,
};

use crate::error::BitwardenError;

/// UniFFI wrapper for `bitwarden_auth::login::LoginClient`.
///
/// The wrapper exists so every exported method declares `BitwardenError` as its error type. When an
/// input argument fails to parse, UniFFI panics instead of returning an error if the produced error
/// type does not match the method's declared one — and the converter registered by
/// `setup_error_converter` always produces a `BitwardenError`. Exporting the `bitwarden_auth`
/// methods directly would declare `PasswordPreloginError` / `PasswordLoginError` instead and panic;
/// `login_via_password` is reachable that way through the `NonZeroU32` KDF fields, which are a
/// `uniffi::custom_type!` that rejects zero.
#[derive(uniffi::Object)]
pub struct LoginClient(pub(crate) bitwarden_auth::login::LoginClient);

#[uniffi::export(async_runtime = "tokio")]
impl LoginClient {
    /// Retrieves the data required before authenticating with a password.
    /// This includes the user's KDF configuration needed to properly derive the master key.
    pub async fn get_password_prelogin(
        &self,
        email: String,
    ) -> Result<PasswordPreloginResponse, BitwardenError> {
        Ok(self.0.get_password_prelogin(email).await?)
    }

    /// Authenticates a user via email and master password.
    ///
    /// Derives the master password hash using KDF settings from prelogin, then sends
    /// the authentication request to obtain access tokens and vault keys.
    pub async fn login_via_password(
        &self,
        request: PasswordLoginRequest,
    ) -> Result<LoginResponse, BitwardenError> {
        Ok(self.0.login_via_password(request).await?)
    }
}
