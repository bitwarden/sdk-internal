use bitwarden_core::key_management::{MasterPasswordError, MasterPasswordUnlockData};
use serde::{Deserialize, Serialize};

use crate::identity::{
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
            trusted_device_option: match api.trusted_device_option {
                Some(tde) => Some(tde.into()),
                None => None,
            },
            key_connector_option: match api.key_connector_option {
                Some(kc) => Some(kc.into()),
                None => None,
            },
            webauthn_prf_option: match api.webauthn_prf_option {
                Some(wa) => Some(wa.into()),
                None => None,
            },
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
    use crate::identity::api::response::{
        KeyConnectorUserDecryptionOptionApiResponse, TrustedDeviceUserDecryptionOptionApiResponse,
        WebAuthnPrfUserDecryptionOptionApiResponse,
    };

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
                master_key_encrypted_user_key: Some(
                    "2.q/2tw0ANVGbyBaS+RxLdNw==|mIreJLpxs/pkCCWEn/L/CA==".to_string(),
                ),
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
        const TDE_ENCRYPTED_PRIVATE_KEY: &str = "2.test|encrypted";
        const TDE_ENCRYPTED_USER_KEY: &str = "2.test|encrypted2";
        const KEY_CONNECTOR_URL: &str = "https://key-connector.bitwarden.com";
        const WEBAUTHN_ENCRYPTED_PRIVATE_KEY: &str = "2.test|encrypted3";
        const WEBAUTHN_ENCRYPTED_USER_KEY: &str = "2.test|encrypted4";

        let api = UserDecryptionOptionsApiResponse {
            master_password_unlock: Some(MasterPasswordUnlockResponseModel {
                kdf: Box::new(MasterPasswordUnlockKdfResponseModel {
                    kdf_type: KdfType::PBKDF2_SHA256,
                    iterations: KDF_ITERATIONS as i32,
                    memory: None,
                    parallelism: None,
                }),
                master_key_encrypted_user_key: Some(
                    "2.q/2tw0ANVGbyBaS+RxLdNw==|mIreJLpxs/pkCCWEn/L/CA==".to_string(),
                ),
                salt: Some(SALT.to_string()),
            }),
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
    }
}
