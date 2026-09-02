use bitwarden_auth::login::{
    login_via_password::{PasswordLoginRequest, PasswordPreloginResponse},
    models::LoginResponse,
};

use crate::error::BitwardenError;

// This wrapper exists so each exported method declares `BitwardenError` as its error type.
// UniFFI panics when an argument fails to lift and the produced error type does not match the
// method's declared error type. The converter registered by `setup_error_converter` always
// produces a `BitwardenError`.
// Exporting `bitwarden_auth::login::LoginClient` directly would declare `PasswordPreloginError`
// or `PasswordLoginError` instead. That mismatch would make the method panic instead of
// returning an error.
// A caller can trigger this panic in `login_via_password` through a zero value in a
// `NonZeroU32` KDF field.

/// Client for authenticating a user against the Identity API.
///
/// Obtain one via [`crate::auth::AuthClient::login`].
#[derive(uniffi::Object)]
pub struct LoginClient(pub(crate) bitwarden_auth::login::LoginClient);

#[uniffi::export(async_runtime = "tokio")]
impl LoginClient {
    /// Retrieves the data required before authenticating with a password.
    pub async fn get_password_prelogin(
        &self,
        email: String,
    ) -> Result<PasswordPreloginResponse, BitwardenError> {
        Ok(self.0.get_password_prelogin(email).await?)
    }

    /// Authenticates a user via email and master password.
    ///
    /// Derives the master password hash using the prelogin response, then sends
    /// the authentication request to obtain access tokens and vault keys.
    pub async fn login_via_password(
        &self,
        request: PasswordLoginRequest,
    ) -> Result<LoginResponse, BitwardenError> {
        Ok(self.0.login_via_password(request).await?)
    }
}
