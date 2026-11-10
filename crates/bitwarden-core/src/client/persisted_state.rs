//! Persisted state types and setting keys for the Bitwarden SDK.

use bitwarden_crypto::{EncString, UnsignedSharedKey, safe::SymmetricKeyEnvelope};
use bitwarden_state::{register_repository_item, register_setting_key};
use serde::{Deserialize, Deserializer, Serialize};

use super::{flags::Flags, login_method::UserLoginMethod};
use crate::{
    OrganizationId, ProviderId, UserId,
    key_management::account_cryptographic_state::WrappedAccountCryptographicState,
};

/// A persisted organization encryption key.
///
/// Stored in a Repository keyed by [`OrganizationId`].
/// The `org_id` is included in the struct so it can be recovered from `Repository::list()`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct OrganizationSharedKey {
    /// The organization this key belongs to.
    pub org_id: OrganizationId,
    /// The organization's encryption key, protected for the current user.
    pub key: OrganizationKeyEnvelope,
}

register_repository_item!(OrganizationId => OrganizationSharedKey, "OrganizationSharedKey");

/// How an organization key is protected, as delivered by the server on sync.
///
/// Deserialization also accepts a bare [`UnsignedSharedKey`] string as
/// [`OrganizationKeyEnvelope::Organization`]. That is how [`OrganizationSharedKey`] was persisted
/// before provider-wrapped keys were supported, so existing rows load without a migration.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[bitwarden_ffi::wasm_record]
pub enum OrganizationKeyEnvelope {
    /// Encapsulated to the user's public key (`profile.organizations[].key`).
    Organization {
        /// The organization key, encapsulated to the user's public key.
        key: UnsignedSharedKey,
    },
    /// Wrapped by a provider key (`profile.providerOrganizations[].key`).
    Provider {
        /// The provider whose key wraps the organization key.
        provider_id: ProviderId,
        /// The organization key, wrapped by the provider key.
        key: EncString,
    },
}

impl<'de> Deserialize<'de> for OrganizationKeyEnvelope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        /// Mirrors the serialized form of [`OrganizationKeyEnvelope`].
        #[derive(Deserialize)]
        #[serde(tag = "type", rename_all = "camelCase")]
        enum Tagged {
            Organization {
                key: UnsignedSharedKey,
            },
            Provider {
                provider_id: ProviderId,
                key: EncString,
            },
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Tagged(Tagged),
            /// The format written before [`OrganizationKeyEnvelope`] existed.
            Legacy(UnsignedSharedKey),
        }

        Ok(match Repr::deserialize(deserializer)? {
            Repr::Tagged(Tagged::Organization { key }) | Repr::Legacy(key) => {
                Self::Organization { key }
            }
            Repr::Tagged(Tagged::Provider { provider_id, key }) => {
                Self::Provider { provider_id, key }
            }
        })
    }
}

/// A persisted provider encryption key, encapsulated to the user's public key
/// (`profile.providers[].key`).
///
/// Stored in a Repository keyed by [`ProviderId`].
/// The `provider_id` is included in the struct so it can be recovered from `Repository::list()`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[bitwarden_ffi::wasm_record]
pub struct ProviderSharedKey {
    /// The provider this key belongs to.
    pub provider_id: ProviderId,
    /// The provider's encryption key, encapsulated to the user's public key.
    pub key: UnsignedSharedKey,
}

register_repository_item!(ProviderId => ProviderSharedKey, "ProviderSharedKey");

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
    pub const USER_ID: UserId = "user_id"
);
register_setting_key!(
    /// Setting key for the active user's email.
    pub const USER_EMAIL: String = "user_email"
);
register_setting_key!(
    /// Setting key for feature flags.
    pub const FLAGS: Flags = "flags"
);
register_setting_key!(
    /// Setting key for the timestamp at which feature flags were last fetched from `/config`.
    pub const FLAGS_FETCHED_AT: chrono::DateTime<chrono::Utc> = "flags_fetched_at"
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
    pub const SESSION_PROTECTED_USER_KEY: SymmetricKeyEnvelope = "session_protected_user_key"
);

#[cfg(test)]
mod tests {
    use super::*;

    const ORG_ID: &str = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8";
    const PROVIDER_ID: &str = "8d37d5c2-6f19-4c2b-9d8f-6b0a0c3a1e42";
    const UNSIGNED_SHARED_KEY: &str = "4.rY01mZFXHOsBAg5Fq4gyXuklWfm6mQASm42DJpx05a+e2mmp+P5W6r54WU2hlREX0uoTxyP91bKKwickSPdCQQ58J45LXHdr9t2uzOYyjVzpzebFcdMw1eElR9W2DW8wEk9+mvtWvKwu7yTebzND+46y1nRMoFydi5zPVLSlJEf81qZZ4Uh1UUMLwXz+NRWfixnGXgq2wRq1bH0n3mqDhayiG4LJKgGdDjWXC8W8MMXDYx24SIJrJu9KiNEMprJE+XVF9nQVNijNAjlWBqkDpsfaWTUfeVLRLctfAqW1blsmIv4RQ91PupYJZDNc8nO9ZTF3TEVM+2KHoxzDJrLs2Q==";
    const ENC_STRING: &str = "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE=";

    /// Rows persisted before [`OrganizationKeyEnvelope`] existed hold the key as a bare string.
    #[test]
    fn test_organization_shared_key_deserializes_legacy_row() {
        let row = serde_json::json!({ "org_id": ORG_ID, "key": UNSIGNED_SHARED_KEY });

        let key: OrganizationSharedKey = serde_json::from_value(row).unwrap();

        assert_eq!(key.org_id.to_string(), ORG_ID);
        let OrganizationKeyEnvelope::Organization { key } = key.key else {
            panic!("legacy row should deserialize as the organization variant");
        };
        assert_eq!(key.to_string(), UNSIGNED_SHARED_KEY);
    }

    #[test]
    fn test_organization_key_envelope_organization_round_trips() {
        let envelope = OrganizationKeyEnvelope::Organization {
            key: UNSIGNED_SHARED_KEY.parse().unwrap(),
        };

        let json = serde_json::to_value(&envelope).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "type": "organization", "key": UNSIGNED_SHARED_KEY })
        );

        let OrganizationKeyEnvelope::Organization { key } = serde_json::from_value(json).unwrap()
        else {
            panic!("should deserialize as the organization variant");
        };
        assert_eq!(key.to_string(), UNSIGNED_SHARED_KEY);
    }

    #[test]
    fn test_organization_key_envelope_provider_round_trips() {
        let envelope = OrganizationKeyEnvelope::Provider {
            provider_id: PROVIDER_ID.parse().unwrap(),
            key: ENC_STRING.parse().unwrap(),
        };

        let json = serde_json::to_value(&envelope).unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "type": "provider", "provider_id": PROVIDER_ID, "key": ENC_STRING })
        );

        let OrganizationKeyEnvelope::Provider { provider_id, key } =
            serde_json::from_value(json).unwrap()
        else {
            panic!("should deserialize as the provider variant");
        };
        assert_eq!(provider_id.to_string(), PROVIDER_ID);
        assert_eq!(key.to_string(), ENC_STRING);
    }

    #[test]
    fn test_organization_key_envelope_rejects_unknown_type() {
        let json = serde_json::json!({ "type": "unknown", "key": UNSIGNED_SHARED_KEY });

        assert!(serde_json::from_value::<OrganizationKeyEnvelope>(json).is_err());
    }
}
