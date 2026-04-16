//! Persisted state types and setting keys for the Bitwarden SDK.

use bitwarden_crypto::{EncString, UnsignedSharedKey};
use bitwarden_state::{register_repository_item, register_setting_key};
use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify::Tsify;

use super::{flags::Flags, login_method::UserLoginMethod};
use crate::{
    OrganizationId, key_management::account_cryptographic_state::WrappedAccountCryptographicState,
};

/// A persisted organization encryption key.
///
/// Stored in a Repository keyed by [`OrganizationId`].
/// The `org_id` is included in the struct so it can be recovered from `Repository::list()`.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
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

// Setting keys
register_setting_key!(
    /// Setting key for the user's login method.
    pub const USER_LOGIN_METHOD: UserLoginMethod = "user_login_method"
);
register_setting_key!(
    /// Setting key for the base API URLs.
    pub const BASE_URLS: BaseUrls = "base_urls"
);
register_setting_key!(
    /// Setting key for the user ID.
    pub const USER_ID: String = "user_id"
);
register_setting_key!(
    /// Setting key for feature flags.
    pub const FLAGS: Flags = "flags"
);
register_setting_key!(
    /// Setting key for authentication tokens.
    pub const AUTHENTICATION_TOKENS: AuthenticationTokens = "authentication_tokens"
);
register_setting_key!(
    /// Setting key for the account cryptographic state.
    pub const ACCOUNT_CRYPTO_STATE: WrappedAccountCryptographicState = "account_crypto_state"
);
register_setting_key!(
    /// Setting key for the session-protected user key.
    pub const SESSION_PROTECTED_USER_KEY: EncString = "session_protected_user_key"
);
