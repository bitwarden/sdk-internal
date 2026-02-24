use bitwarden_core::key_management::{MasterPasswordError, MasterPasswordUnlockData};
use serde::{Deserialize, Serialize};

use crate::login::{
    api::response::UserDecryptionOptionsApiResponse,
    models::{
        KeyConnectorUserDecryptionOption, TrustedDeviceUserDecryptionOption,
        WebAuthnPrfUserDecryptionOption,
    },
};

/// SDK domain model for user decryption options.
/// Provides the various methods available to unlock a user's vault.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(
    feature = "wasm",
    derive(tsify::Tsify),
    tsify(into_wasm_abi, from_wasm_abi)
)]
pub struct UserDecryptionOptionsResponse {
    /// Master password unlock option. None if user doesn't have a master password.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub master_password_unlock: Option<MasterPasswordUnlockData>,

    /// Trusted Device decryption option.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_device_option: Option<TrustedDeviceUserDecryptionOption>,

    /// Key Connector decryption option.
    /// Mutually exclusive with Trusted Device option.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_connector_option: Option<KeyConnectorUserDecryptionOption>,

    /// WebAuthn PRF decryption option.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webauthn_prf_option: Option<WebAuthnPrfUserDecryptionOption>,
}

impl TryFrom<UserDecryptionOptionsApiResponse> for UserDecryptionOptionsResponse {
    type Error = MasterPasswordError;

    fn try_from(api: UserDecryptionOptionsApiResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            master_password_unlock: match api.master_password_unlock {
                Some(ref mp) => Some(MasterPasswordUnlockData::try_from(mp)?),
                None => None,
            },
            trusted_device_option: api.trusted_device_option.map(|tde| tde.into()),
            key_connector_option: api.key_connector_option.map(|kc| kc.into()),
            webauthn_prf_option: api.webauthn_prf_option.map(|wa| wa.into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::{
        KdfType, MasterPasswordUnlockKdfResponseModel, MasterPasswordUnlockResponseModel,
    };
    use bitwarden_crypto::Kdf;

    use super::*;
    use crate::login::api::response::{
        KeyConnectorUserDecryptionOptionApiResponse, TrustedDeviceUserDecryptionOptionApiResponse,
        WebAuthnPrfUserDecryptionOptionApiResponse,
    };

    const MASTER_KEY_ENCRYPTED_USER_KEY: &str = "2.Q/2PhzcC7GdeiMHhWguYAQ==|GpqzVdr0go0ug5cZh1n+uixeBC3oC90CIe0hd/HWA/pTRDZ8ane4fmsEIcuc8eMKUt55Y2q/fbNzsYu41YTZzzsJUSeqVjT8/iTQtgnNdpo=|dwI+uyvZ1h/iZ03VQ+/wrGEFYVewBUUl/syYgjsNMbE=";

    #[test]
    fn test_user_decryption_options_conversion_with_master_password() {
        let api = UserDecryptionOptionsApiResponse {
            master_password_unlock: Some(MasterPasswordUnlockResponseModel {
                kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                    kdf_type: KdfType::PBKDF2_SHA256,
                    iterations: 600000,
                    memory: None,
                    parallelism: None,
                }),
                master_key_encrypted_user_key: Some(MASTER_KEY_ENCRYPTED_USER_KEY.to_string()),
                salt: Some("test@example.com".to_string()),
            }),
            trusted_device_option: None,
            key_connector_option: None,
            webauthn_prf_option: None,
        };

        let domain: UserDecryptionOptionsResponse = api.try_into().unwrap();

        assert!(domain.master_password_unlock.is_some());
        let mp_unlock = domain.master_password_unlock.unwrap();
        assert_eq!(mp_unlock.salt, "test@example.com");
        match mp_unlock.kdf {
            Kdf::PBKDF2 { iterations } => {
                assert_eq!(iterations.get(), 600000);
            }
            _ => panic!("Expected PBKDF2 KDF"),
        }
        assert!(domain.trusted_device_option.is_none());
        assert!(domain.key_connector_option.is_none());
        assert!(domain.webauthn_prf_option.is_none());
    }

    #[test]
    fn test_user_decryption_options_conversion_with_all_options() {
        // Test data constants
        const SALT: &str = "test@example.com";
        const KDF_ITERATIONS: u32 = 600000;
        const TDE_ENCRYPTED_PRIVATE_KEY: &str = "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=";
        const TDE_ENCRYPTED_USER_KEY: &str = "4.ZheRb3PCfAunyFdQYPfyrFqpuvmln9H9w5nDjt88i5A7ug1XE0LJdQHCIYJl0YOZ1gCOGkhFu/CRY2StiLmT3iRKrrVBbC1+qRMjNNyDvRcFi91LWsmRXhONVSPjywzrJJXglsztDqGkLO93dKXNhuKpcmtBLsvgkphk/aFvxbaOvJ/FHdK/iV0dMGNhc/9tbys8laTdwBlI5xIChpRcrfH+XpSFM88+Bu03uK67N9G6eU1UmET+pISJwJvMuIDMqH+qkT7OOzgL3t6I0H2LDj+CnsumnQmDsvQzDiNfTR0IgjpoE9YH2LvPXVP2wVUkiTwXD9cG/E7XeoiduHyHjw==";
        const KEY_CONNECTOR_URL: &str = "https://key-connector.bitwarden.com";
        const WEBAUTHN_ENCRYPTED_PRIVATE_KEY: &str = "2.fkvl0+sL1lwtiOn1eewsvQ==|dT0TynLl8YERZ8x7dxC+DQ==|cWhiRSYHOi/AA2LiV/JBJWbO9C7pbUpOM6TMAcV47hE=";
        const WEBAUTHN_ENCRYPTED_USER_KEY: &str = "4.DMD1D5r6BsDDd7C/FE1eZbMCKrmryvAsCKj6+bO54gJNUxisOI7SDcpPLRXf+JdhqY15pT+wimQ5cD9C+6OQ6s71LFQHewXPU29l9Pa1JxGeiKqp37KLYf+1IS6UB2K3ANN35C52ZUHh2TlzIS5RuntxnpCw7APbcfpcnmIdLPJBtuj/xbFd6eBwnI3GSe5qdS6/Ixdd0dgsZcpz3gHJBKmIlSo0YN60SweDq3kTJwox9xSqdCueIDg5U4khc7RhjYx8b33HXaNJj3DwgIH8iLj+lqpDekogr630OhHG3XRpvl4QzYO45bmHb8wAh67Dj70nsZcVg6bAEFHdSFohww==";

        let api = UserDecryptionOptionsApiResponse {
            master_password_unlock: Some(MasterPasswordUnlockResponseModel {
                kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                    kdf_type: KdfType::PBKDF2_SHA256,
                    iterations: KDF_ITERATIONS as i32,
                    memory: None,
                    parallelism: None,
                }),
                master_key_encrypted_user_key: Some(MASTER_KEY_ENCRYPTED_USER_KEY.to_string()),
                salt: Some(SALT.to_string()),
            }),
            // Note: the trusted device option && the key connector option are mutually exclusive
            // from the server, but this test is just verifying that the conversion logic works
            // for all option types.
            trusted_device_option: Some(TrustedDeviceUserDecryptionOptionApiResponse {
                has_admin_approval: true,
                has_login_approving_device: false,
                has_manage_reset_password_permission: false,
                is_tde_offboarding: false,
                encrypted_private_key: Some(TDE_ENCRYPTED_PRIVATE_KEY.parse().unwrap()),
                encrypted_user_key: Some(TDE_ENCRYPTED_USER_KEY.parse().unwrap()),
            }),
            key_connector_option: Some(KeyConnectorUserDecryptionOptionApiResponse {
                key_connector_url: KEY_CONNECTOR_URL.to_string(),
            }),
            webauthn_prf_option: Some(WebAuthnPrfUserDecryptionOptionApiResponse {
                encrypted_private_key: WEBAUTHN_ENCRYPTED_PRIVATE_KEY.parse().unwrap(),
                encrypted_user_key: WEBAUTHN_ENCRYPTED_USER_KEY.parse().unwrap(),
                credential_id: None,
                transports: None,
            }),
        };

        let domain: UserDecryptionOptionsResponse = api.try_into().unwrap();

        // Verify master password unlock
        assert!(domain.master_password_unlock.is_some());
        let mp_unlock = domain.master_password_unlock.unwrap();
        assert_eq!(mp_unlock.salt, SALT);
        match mp_unlock.kdf {
            Kdf::PBKDF2 { iterations } => {
                assert_eq!(iterations.get(), KDF_ITERATIONS);
            }
            _ => panic!("Expected PBKDF2 KDF"),
        }

        // Verify trusted device option
        assert!(domain.trusted_device_option.is_some());
        let tde = domain.trusted_device_option.unwrap();
        assert!(tde.has_admin_approval);
        assert!(!tde.has_login_approving_device);
        assert!(!tde.has_manage_reset_password_permission);
        assert!(!tde.is_tde_offboarding);
        assert_eq!(
            tde.encrypted_private_key,
            Some(TDE_ENCRYPTED_PRIVATE_KEY.parse().unwrap())
        );
        assert_eq!(
            tde.encrypted_user_key,
            Some(TDE_ENCRYPTED_USER_KEY.parse().unwrap())
        );

        // Verify key connector option
        assert!(domain.key_connector_option.is_some());
        let kc = domain.key_connector_option.unwrap();
        assert_eq!(kc.key_connector_url, KEY_CONNECTOR_URL);

        // Verify webauthn prf option
        assert!(domain.webauthn_prf_option.is_some());
        let webauthn = domain.webauthn_prf_option.unwrap();
        assert_eq!(
            webauthn.encrypted_private_key,
            WEBAUTHN_ENCRYPTED_PRIVATE_KEY.parse().unwrap()
        );
        assert_eq!(
            webauthn.encrypted_user_key,
            WEBAUTHN_ENCRYPTED_USER_KEY.parse().unwrap()
        );
        assert_eq!(webauthn.credential_id, None);
        assert_eq!(webauthn.transports, None);
    }

    #[test]
    fn test_user_decryption_options_with_trusted_device_only() {
        const TDE_ENCRYPTED_PRIVATE_KEY: &str = "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=";
        const TDE_ENCRYPTED_USER_KEY: &str = "4.ZheRb3PCfAunyFdQYPfyrFqpuvmln9H9w5nDjt88i5A7ug1XE0LJdQHCIYJl0YOZ1gCOGkhFu/CRY2StiLmT3iRKrrVBbC1+qRMjNNyDvRcFi91LWsmRXhONVSPjywzrJJXglsztDqGkLO93dKXNhuKpcmtBLsvgkphk/aFvxbaOvJ/FHdK/iV0dMGNhc/9tbys8laTdwBlI5xIChpRcrfH+XpSFM88+Bu03uK67N9G6eU1UmET+pISJwJvMuIDMqH+qkT7OOzgL3t6I0H2LDj+CnsumnQmDsvQzDiNfTR0IgjpoE9YH2LvPXVP2wVUkiTwXD9cG/E7XeoiduHyHjw==";

        let api = UserDecryptionOptionsApiResponse {
            master_password_unlock: None,
            trusted_device_option: Some(TrustedDeviceUserDecryptionOptionApiResponse {
                has_admin_approval: false,
                has_login_approving_device: true,
                has_manage_reset_password_permission: false,
                is_tde_offboarding: false,
                encrypted_private_key: Some(TDE_ENCRYPTED_PRIVATE_KEY.parse().unwrap()),
                encrypted_user_key: Some(TDE_ENCRYPTED_USER_KEY.parse().unwrap()),
            }),
            key_connector_option: None,
            webauthn_prf_option: None,
        };

        let domain: UserDecryptionOptionsResponse = api.try_into().unwrap();

        assert!(domain.master_password_unlock.is_none());
        assert!(domain.trusted_device_option.is_some());
        assert!(domain.key_connector_option.is_none());
        assert!(domain.webauthn_prf_option.is_none());

        let tde = domain.trusted_device_option.unwrap();
        assert!(!tde.has_admin_approval);
        assert!(tde.has_login_approving_device);
        assert_eq!(
            tde.encrypted_private_key,
            Some(TDE_ENCRYPTED_PRIVATE_KEY.parse().unwrap())
        );
        assert_eq!(
            tde.encrypted_user_key,
            Some(TDE_ENCRYPTED_USER_KEY.parse().unwrap())
        );
    }

    #[test]
    fn test_user_decryption_options_with_key_connector_only() {
        const KEY_CONNECTOR_URL: &str = "https://key-connector.example.com";

        let api = UserDecryptionOptionsApiResponse {
            master_password_unlock: None,
            trusted_device_option: None,
            key_connector_option: Some(KeyConnectorUserDecryptionOptionApiResponse {
                key_connector_url: KEY_CONNECTOR_URL.to_string(),
            }),
            webauthn_prf_option: None,
        };

        let domain: UserDecryptionOptionsResponse = api.try_into().unwrap();

        assert!(domain.master_password_unlock.is_none());
        assert!(domain.trusted_device_option.is_none());
        assert!(domain.key_connector_option.is_some());
        assert!(domain.webauthn_prf_option.is_none());

        let kc = domain.key_connector_option.unwrap();
        assert_eq!(kc.key_connector_url, KEY_CONNECTOR_URL);
    }

    #[test]
    fn test_user_decryption_options_with_webauthn_prf_only() {
        const WEBAUTHN_ENCRYPTED_PRIVATE_KEY: &str = "2.fkvl0+sL1lwtiOn1eewsvQ==|dT0TynLl8YERZ8x7dxC+DQ==|cWhiRSYHOi/AA2LiV/JBJWbO9C7pbUpOM6TMAcV47hE=";
        const WEBAUTHN_ENCRYPTED_USER_KEY: &str = "4.DMD1D5r6BsDDd7C/FE1eZbMCKrmryvAsCKj6+bO54gJNUxisOI7SDcpPLRXf+JdhqY15pT+wimQ5cD9C+6OQ6s71LFQHewXPU29l9Pa1JxGeiKqp37KLYf+1IS6UB2K3ANN35C52ZUHh2TlzIS5RuntxnpCw7APbcfpcnmIdLPJBtuj/xbFd6eBwnI3GSe5qdS6/Ixdd0dgsZcpz3gHJBKmIlSo0YN60SweDq3kTJwox9xSqdCueIDg5U4khc7RhjYx8b33HXaNJj3DwgIH8iLj+lqpDekogr630OhHG3XRpvl4QzYO45bmHb8wAh67Dj70nsZcVg6bAEFHdSFohww==";

        let api = UserDecryptionOptionsApiResponse {
            master_password_unlock: None,
            trusted_device_option: None,
            key_connector_option: None,
            webauthn_prf_option: Some(WebAuthnPrfUserDecryptionOptionApiResponse {
                encrypted_private_key: WEBAUTHN_ENCRYPTED_PRIVATE_KEY.parse().unwrap(),
                encrypted_user_key: WEBAUTHN_ENCRYPTED_USER_KEY.parse().unwrap(),
                credential_id: None,
                transports: None,
            }),
        };

        let domain: UserDecryptionOptionsResponse = api.try_into().unwrap();

        assert!(domain.master_password_unlock.is_none());
        assert!(domain.trusted_device_option.is_none());
        assert!(domain.key_connector_option.is_none());
        assert!(domain.webauthn_prf_option.is_some());

        let webauthn = domain.webauthn_prf_option.unwrap();
        assert_eq!(
            webauthn.encrypted_private_key,
            WEBAUTHN_ENCRYPTED_PRIVATE_KEY.parse().unwrap()
        );
        assert_eq!(
            webauthn.encrypted_user_key,
            WEBAUTHN_ENCRYPTED_USER_KEY.parse().unwrap()
        );
        assert_eq!(webauthn.credential_id, None);
        assert_eq!(webauthn.transports, None);
    }

    #[test]
    fn test_user_decryption_options_with_no_options() {
        let api = UserDecryptionOptionsApiResponse {
            master_password_unlock: None,
            trusted_device_option: None,
            key_connector_option: None,
            webauthn_prf_option: None,
        };

        let domain: UserDecryptionOptionsResponse = api.try_into().unwrap();

        assert!(domain.master_password_unlock.is_none());
        assert!(domain.trusted_device_option.is_none());
        assert!(domain.key_connector_option.is_none());
        assert!(domain.webauthn_prf_option.is_none());
    }

    #[test]
    fn test_user_decryption_options_with_master_password_and_trusted_device() {
        const TDE_ENCRYPTED_PRIVATE_KEY: &str = "2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=";
        const TDE_ENCRYPTED_USER_KEY: &str = "4.ZheRb3PCfAunyFdQYPfyrFqpuvmln9H9w5nDjt88i5A7ug1XE0LJdQHCIYJl0YOZ1gCOGkhFu/CRY2StiLmT3iRKrrVBbC1+qRMjNNyDvRcFi91LWsmRXhONVSPjywzrJJXglsztDqGkLO93dKXNhuKpcmtBLsvgkphk/aFvxbaOvJ/FHdK/iV0dMGNhc/9tbys8laTdwBlI5xIChpRcrfH+XpSFM88+Bu03uK67N9G6eU1UmET+pISJwJvMuIDMqH+qkT7OOzgL3t6I0H2LDj+CnsumnQmDsvQzDiNfTR0IgjpoE9YH2LvPXVP2wVUkiTwXD9cG/E7XeoiduHyHjw==";

        let api = UserDecryptionOptionsApiResponse {
            master_password_unlock: Some(MasterPasswordUnlockResponseModel {
                kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                    kdf_type: KdfType::PBKDF2_SHA256,
                    iterations: 600000,
                    memory: None,
                    parallelism: None,
                }),
                master_key_encrypted_user_key: Some(MASTER_KEY_ENCRYPTED_USER_KEY.to_string()),
                salt: Some("test@example.com".to_string()),
            }),
            trusted_device_option: Some(TrustedDeviceUserDecryptionOptionApiResponse {
                has_admin_approval: true,
                has_login_approving_device: false,
                has_manage_reset_password_permission: true,
                is_tde_offboarding: false,
                encrypted_private_key: Some(TDE_ENCRYPTED_PRIVATE_KEY.parse().unwrap()),
                encrypted_user_key: Some(TDE_ENCRYPTED_USER_KEY.parse().unwrap()),
            }),
            key_connector_option: None,
            webauthn_prf_option: None,
        };

        let domain: UserDecryptionOptionsResponse = api.try_into().unwrap();

        assert!(domain.master_password_unlock.is_some());
        assert!(domain.trusted_device_option.is_some());
        assert!(domain.key_connector_option.is_none());
        assert!(domain.webauthn_prf_option.is_none());
    }

    #[test]
    fn test_user_decryption_options_with_master_password_and_key_connector() {
        const KEY_CONNECTOR_URL: &str = "https://key-connector.example.com";

        let api = UserDecryptionOptionsApiResponse {
            master_password_unlock: Some(MasterPasswordUnlockResponseModel {
                kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                    kdf_type: KdfType::PBKDF2_SHA256,
                    iterations: 600000,
                    memory: None,
                    parallelism: None,
                }),
                master_key_encrypted_user_key: Some(MASTER_KEY_ENCRYPTED_USER_KEY.to_string()),
                salt: Some("test@example.com".to_string()),
            }),
            trusted_device_option: None,
            key_connector_option: Some(KeyConnectorUserDecryptionOptionApiResponse {
                key_connector_url: KEY_CONNECTOR_URL.to_string(),
            }),
            webauthn_prf_option: None,
        };

        let domain: UserDecryptionOptionsResponse = api.try_into().unwrap();

        assert!(domain.master_password_unlock.is_some());
        assert!(domain.trusted_device_option.is_none());
        assert!(domain.key_connector_option.is_some());
        assert!(domain.webauthn_prf_option.is_none());
    }

    #[test]
    fn test_user_decryption_options_with_master_password_and_webauthn_prf() {
        const WEBAUTHN_ENCRYPTED_PRIVATE_KEY: &str = "2.fkvl0+sL1lwtiOn1eewsvQ==|dT0TynLl8YERZ8x7dxC+DQ==|cWhiRSYHOi/AA2LiV/JBJWbO9C7pbUpOM6TMAcV47hE=";
        const WEBAUTHN_ENCRYPTED_USER_KEY: &str = "4.DMD1D5r6BsDDd7C/FE1eZbMCKrmryvAsCKj6+bO54gJNUxisOI7SDcpPLRXf+JdhqY15pT+wimQ5cD9C+6OQ6s71LFQHewXPU29l9Pa1JxGeiKqp37KLYf+1IS6UB2K3ANN35C52ZUHh2TlzIS5RuntxnpCw7APbcfpcnmIdLPJBtuj/xbFd6eBwnI3GSe5qdS6/Ixdd0dgsZcpz3gHJBKmIlSo0YN60SweDq3kTJwox9xSqdCueIDg5U4khc7RhjYx8b33HXaNJj3DwgIH8iLj+lqpDekogr630OhHG3XRpvl4QzYO45bmHb8wAh67Dj70nsZcVg6bAEFHdSFohww==";

        let api = UserDecryptionOptionsApiResponse {
            master_password_unlock: Some(MasterPasswordUnlockResponseModel {
                kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                    kdf_type: KdfType::PBKDF2_SHA256,
                    iterations: 600000,
                    memory: None,
                    parallelism: None,
                }),
                master_key_encrypted_user_key: Some(MASTER_KEY_ENCRYPTED_USER_KEY.to_string()),
                salt: Some("test@example.com".to_string()),
            }),
            trusted_device_option: None,
            key_connector_option: None,
            webauthn_prf_option: Some(WebAuthnPrfUserDecryptionOptionApiResponse {
                encrypted_private_key: WEBAUTHN_ENCRYPTED_PRIVATE_KEY.parse().unwrap(),
                encrypted_user_key: WEBAUTHN_ENCRYPTED_USER_KEY.parse().unwrap(),
                credential_id: None,
                transports: None,
            }),
        };

        let domain: UserDecryptionOptionsResponse = api.try_into().unwrap();

        assert!(domain.master_password_unlock.is_some());
        assert!(domain.trusted_device_option.is_none());
        assert!(domain.key_connector_option.is_none());
        assert!(domain.webauthn_prf_option.is_some());
    }
}
