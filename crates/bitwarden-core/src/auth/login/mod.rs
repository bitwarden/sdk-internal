pub mod response;

#[cfg(feature = "internal")]
mod prelogin;
#[cfg(feature = "internal")]
pub use prelogin::*;

#[cfg(any(feature = "internal", feature = "secrets"))]
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

#[cfg(feature = "secrets")]
mod access_token;
#[cfg(feature = "secrets")]
pub use access_token::*;

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error(transparent)]
    Api(#[from] crate::ApiError),
    #[error(transparent)]
    Crypto(#[from] bitwarden_crypto::CryptoError),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    InvalidBase64(#[from] base64::DecodeError),

    #[error(transparent)]
    MissingField(#[from] crate::MissingFieldError),

    #[error(transparent)]
    JwtTokenParse(#[from] super::JwtTokenParseError),
    #[error("JWT token is missing email")]
    JwtTokenMissingEmail,

    #[error(transparent)]
    Prelogin(#[from] PreloginError),
    #[error(transparent)]
    EncryptionSettings(#[from] crate::client::encryption_settings::EncryptionSettingsError),
    #[error(transparent)]
    AccessTokenInvalid(#[from] super::AccessTokenInvalidError),
    #[error(transparent)]
    NotAuthenticated(#[from] super::NotAuthenticatedError),
    #[cfg(feature = "secrets")]
    #[error(transparent)]
    StateFile(#[from] crate::secrets_manager::state::StateFileError),
    #[error("Error parsing Identity response: {0}")]
    IdentityFail(crate::auth::api::response::IdentityTokenFailResponse),

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
}
