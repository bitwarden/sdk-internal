use bitwarden_crypto::{
    AsymmetricPublicCryptoKey, DeviceKey, EncString, Kdf, SpkiPublicKeyBytes, SymmetricCryptoKey,
    TrustDeviceResponse, UnsignedSharedKey, UserKey,
};
use bitwarden_encoding::B64;

use crate::{
    Client,
    client::{encryption_settings::EncryptionSettingsError, internal::UserKeyState},
};

/// This function generates a new user key and key pair, initializes the client's crypto with the
/// generated user key, and encrypts the user key with the organization public key for admin
/// password reset. If remember_device is true, it also generates a device key.
pub(super) fn make_register_tde_keys(
    client: &Client,
    email: String,
    org_public_key: B64,
    remember_device: bool,
) -> Result<RegisterTdeKeyResponse, EncryptionSettingsError> {
    let public_key =
        AsymmetricPublicCryptoKey::from_der(&SpkiPublicKeyBytes::from(&org_public_key))?;

    let user_key = UserKey::new(SymmetricCryptoKey::make_aes256_cbc_hmac_key());
    let key_pair = user_key.make_key_pair()?;

    let admin_reset = UnsignedSharedKey::encapsulate_key_unsigned(&user_key.0, &public_key)?;

    let device_key = if remember_device {
        Some(DeviceKey::trust_device(&user_key.0)?)
    } else {
        None
    };

    client
        .internal
        .set_login_method(crate::client::LoginMethod::User(
            crate::client::UserLoginMethod::Username {
                client_id: "".to_owned(),
                email,
                kdf: Kdf::default(),
            },
        ));
    client.internal.initialize_user_crypto_decrypted_key(
        user_key.0,
        UserKeyState {
            private_key: key_pair.private.clone(),
            // TODO (https://bitwarden.atlassian.net/browse/PM-21771) Signing keys are not supported on registration yet. This needs to be changed as
            // soon as registration is supported.
            signing_key: None,
            security_state: None,
        },
    )?;

    Ok(RegisterTdeKeyResponse {
        private_key: key_pair.private,
        public_key: key_pair.public,

        admin_reset,
        device_key,
    })
}

#[allow(missing_docs)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RegisterTdeKeyResponse {
    pub private_key: EncString,
    pub public_key: B64,

    pub admin_reset: UnsignedSharedKey,
    pub device_key: Option<TrustDeviceResponse>,
}
