//! Persisted state types and persisted value keys for the Bitwarden SDK.

use bitwarden_crypto::{UnsignedSharedKey, safe::SymmetricKeyEnvelope};
use bitwarden_state::{register_persisted_value, register_repository_item};
use serde::{Deserialize, Serialize};

use super::{flags::Flags, login_method::UserLoginMethod};
use crate::{
    OrganizationId, UserId,
    key_management::account_cryptographic_state::WrappedAccountCryptographicState,
};

/// A persisted organization encryption key.
///
/// Stored in a Repository keyed by [`OrganizationId`].
/// The `org_id` is included in the struct so it can be recovered from `Repository::list()`.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct OrganizationSharedKey {
    /// The organization this key belongs to.
    pub org_id: OrganizationId,
    /// The organization's shared encryption key.
    pub key: UnsignedSharedKey,
}

register_repository_item!(OrganizationId => OrganizationSharedKey, "OrganizationSharedKey");

/// Base API URLs for identity and API services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseUrls {
    /// The identity service URL.
    pub identity_url: String,
    /// The API service URL.
    pub api_url: String,
}

/// Authentication tokens for API access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationTokens {
    /// The access token.
    pub access_token: String,
    /// The refresh token.
    pub refresh_token: Option<String>,
    /// Unix timestamp when the access token expires.
    pub expires_on: i64,
}

// Persisted value keys
register_persisted_value!(
    /// Persisted value key for the user's login method.
    pub USER_LOGIN_METHOD: UserLoginMethod = "user_login_method"
);
register_persisted_value!(
    /// Persisted value key for the base API URLs.
    pub BASE_URLS: BaseUrls = "base_urls"
);
register_persisted_value!(
    /// Persisted value key for the user ID.
    pub USER_ID: UserId = "user_id"
);
register_persisted_value!(
    /// Persisted value key for the active user's email.
    pub USER_EMAIL: String = "user_email"
);
register_persisted_value!(
    /// Persisted value key for feature flags.
    pub FLAGS: Flags = "flags"
);
register_persisted_value!(
    /// Persisted value key for the timestamp at which feature flags were last fetched from `/config`.
    pub FLAGS_FETCHED_AT: chrono::DateTime<chrono::Utc> = "flags_fetched_at"
);
register_persisted_value!(
    /// Persisted value key for authentication tokens.
    pub AUTHENTICATION_TOKENS: AuthenticationTokens = "authentication_tokens"
);
register_persisted_value!(
    /// Persisted value key for the account cryptographic state.
    pub ACCOUNT_CRYPTO_STATE: WrappedAccountCryptographicState = "account_crypto_state"
);
register_persisted_value!(
    /// Persisted value key for the session-protected user key.
    pub SESSION_PROTECTED_USER_KEY: SymmetricKeyEnvelope = "session_protected_user_key"
);
