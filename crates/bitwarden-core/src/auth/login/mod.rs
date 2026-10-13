#[allow(missing_docs)]
pub mod response;

#[cfg(feature = "internal")]
mod prelogin;
#[cfg(feature = "internal")]
pub use prelogin::*;

#[cfg(feature = "internal")]
mod password;
#[cfg(feature = "internal")]
pub use password::*;

#[cfg(feature = "internal")]
mod two_factor;
#[cfg(feature = "internal")]
pub use two_factor::*;

#[cfg(feature = "internal")]
mod api_key;
#[cfg(feature = "internal")]
pub use api_key::*;

#[cfg(feature = "internal")]
mod auth_request;
#[cfg(feature = "internal")]
pub use auth_request::*;

#[allow(missing_docs)]
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error(transparent)]
    Api(#[from] crate::ApiError),
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),

    #[error(transparent)]
    MissingField(#[from] crate::MissingFieldError),

    #[error(transparent)]
    JwtTokenParse(#[from] super::JwtTokenParseError),
    #[error("JWT token is missing email")]
    JwtTokenMissingEmail,

    #[cfg(feature = "internal")]
    #[error(transparent)]
    Prelogin(#[from] PreloginError),
    #[error(transparent)]
    EncryptionSettings(#[from] crate::client::encryption_settings::EncryptionSettingsError),
    #[error(transparent)]
    NotAuthenticated(#[from] super::NotAuthenticatedError),
    #[error("Error parsing Identity response: {0}")]
    IdentityFail(crate::auth::api::response::IdentityTokenFailResponse),

    /// The provided access token could not be parsed. Carries the specific reason so callers see
    /// the real failure detail (e.g. wrong version / wrong parts) rather than a generic error.
    ///
    /// The concrete `AccessTokenInvalidError` type lives in `bitwarden-auth`, which sits above
    /// `bitwarden-core` in the dependency graph, so its message is surfaced as a string here.
    #[error("Invalid access token: {0}")]
    AccessTokenInvalid(String),

    #[error("The state file could not be read")]
    InvalidStateFile,

    #[error("Invalid organization id")]
    InvalidOrganizationId,

    #[error("The response received was invalid and could not be processed")]
    InvalidResponse,

    #[error("Auth request was not approved")]
    AuthRequestNotApproved,

    #[error("Failed to authenticate")]
    AuthenticationFailed,

    #[cfg(feature = "internal")]
    #[error(transparent)]
    MasterPassword(#[from] crate::key_management::MasterPasswordError),
}
