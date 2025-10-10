use std::pin::Pin;

use bitwarden_encoding::B64;
use generic_array::GenericArray;
use rand::Rng;
use typenum::U32;
use zeroize::Zeroize;

use super::{
    kdf::{Kdf, KdfDerivedKeyMaterial},
    utils::stretch_key,
};
use crate::{
    BitwardenLegacyKeyBytes, CryptoError, EncString, KeyDecryptable, Result, SymmetricCryptoKey,
    UserKey,
    util::{self},
};

#[allow(missing_docs)]
#[derive(Copy, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum HashPurpose {
    ServerAuthorization = 1,
    LocalAuthorization = 2,
}

/// Master Key.
///
/// Derived from the users master password, used to protect the [UserKey].
/// TODO: <https://bitwarden.atlassian.net/browse/PM-18366> split KeyConnectorKey into a separate file
#[allow(missing_docs)]
pub enum MasterKey {
    KdfKey(KdfDerivedKeyMaterial),
    KeyConnectorKey(Pin<Box<GenericArray<u8, U32>>>),
}

impl MasterKey {
    pub(crate) fn new(key: KdfDerivedKeyMaterial) -> Self {
        Self::KdfKey(key)
    }

    /// Generate a new random master key for KeyConnector.
    pub fn generate(mut rng: impl rand::RngCore) -> Self {
        let mut key = Box::pin(GenericArray::<u8, U32>::default());

        rng.fill(key.as_mut_slice());
        Self::KeyConnectorKey(key)
    }

    fn inner_bytes(&self) -> &Pin<Box<GenericArray<u8, U32>>> {
        match self {
            Self::KdfKey(key) => &key.0,
            Self::KeyConnectorKey(key) => key,
        }
    }

    /// Derives a users master key from their password, email and KDF.
    ///
    /// Note: the email is trimmed and converted to lowercase before being used.
    pub fn derive(password: &str, email: &str, kdf: &Kdf) -> Result<Self, CryptoError> {
        Ok(KdfDerivedKeyMaterial::derive(password, email, kdf)?.into())
    }

    /// Derive the master key hash, used for local and remote password validation.
    pub fn derive_master_key_hash(&self, password: &[u8], purpose: HashPurpose) -> B64 {
        let hash = util::pbkdf2(self.inner_bytes().as_slice(), password, purpose as u32);

        hash.as_slice().into()
    }

    /// Generate a new random user key and encrypt it with the master key.
    pub fn make_user_key(&self) -> Result<(UserKey, EncString)> {
        make_user_key(rand::thread_rng(), self)
    }

    /// Encrypt the users user key
    pub fn encrypt_user_key(&self, user_key: &SymmetricCryptoKey) -> Result<EncString> {
        encrypt_user_key(self.inner_bytes(), user_key)
    }

    /// Decrypt the users user key
    pub fn decrypt_user_key(&self, user_key: EncString) -> Result<SymmetricCryptoKey> {
        decrypt_user_key(self.inner_bytes(), user_key)
    }

    #[allow(missing_docs)]
    pub fn to_base64(&self) -> B64 {
        B64::from(self.inner_bytes().as_slice())
    }
}

impl TryFrom<&mut [u8]> for MasterKey {
    type Error = CryptoError;

    fn try_from(value: &mut [u8]) -> Result<Self> {
        if value.len() != 32 {
            value.zeroize();
            return Err(CryptoError::InvalidKey);
        }

        let material =
            KdfDerivedKeyMaterial(Box::pin(GenericArray::<u8, U32>::clone_from_slice(value)));
        value.zeroize();
        Ok(Self::new(material))
    }
}

impl From<KdfDerivedKeyMaterial> for MasterKey {
    fn from(key: KdfDerivedKeyMaterial) -> Self {
        Self::new(key)
    }
}

impl TryFrom<&SymmetricCryptoKey> for MasterKey {
    type Error = CryptoError;

    fn try_from(value: &SymmetricCryptoKey) -> Result<Self> {
        match value {
            SymmetricCryptoKey::Aes256CbcKey(key) => {
                Ok(Self::KdfKey(KdfDerivedKeyMaterial(key.enc_key.clone())))
            }
            _ => Err(CryptoError::InvalidKey),
        }
    }
}

/// Helper function to encrypt a user key with a master or pin key.
pub(super) fn encrypt_user_key(
    master_key: &Pin<Box<GenericArray<u8, U32>>>,
    user_key: &SymmetricCryptoKey,
) -> Result<EncString> {
    let stretched_master_key = stretch_key(master_key)?;
    let user_key_bytes = user_key.to_encoded();
    EncString::encrypt_aes256_hmac(user_key_bytes.as_ref(), &stretched_master_key)
}

/// Helper function to decrypt a user key with a master or pin key or key-connector-key.
pub(super) fn decrypt_user_key(
    key: &Pin<Box<GenericArray<u8, U32>>>,
    user_key: EncString,
) -> Result<SymmetricCryptoKey> {
    let dec: Vec<u8> = match user_key {
        // Legacy. user_keys were encrypted using `Aes256Cbc_B64` a long time ago. We've since
        // moved to using `Aes256Cbc_HmacSha256_B64`. However, we still need to support
        // decrypting these old keys.
        EncString::Aes256Cbc_B64 { .. } => {
            let legacy_key = SymmetricCryptoKey::Aes256CbcKey(super::Aes256CbcKey {
                enc_key: Box::pin(GenericArray::clone_from_slice(key)),
            });
            user_key.decrypt_with_key(&legacy_key)?
        }
        EncString::Aes256Cbc_HmacSha256_B64 { .. } => {
            let stretched_key = SymmetricCryptoKey::Aes256CbcHmacKey(stretch_key(key)?);
            user_key.decrypt_with_key(&stretched_key)?
        }
        EncString::Cose_Encrypt0_B64 { .. } => {
            return Err(CryptoError::OperationNotSupported(
                crate::error::UnsupportedOperationError::EncryptionNotImplementedForKey,
            ));
        }
    };

    SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(dec))
}

/// Generate a new random user key and encrypt it with the master key.
///
/// WARNING: This function should only be used with a proper cryptographic random number generator.
/// If you do not have a good reason for using this, use [MasterKey::make_user_key] instead.
///
/// This function is only split out from [MasterKey::make_user_key], to make it unit testable.
fn make_user_key(
    rng: impl rand::RngCore + rand::CryptoRng,
    master_key: &MasterKey,
) -> Result<(UserKey, EncString)> {
    let user_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key_internal(rng);
    let protected = master_key.encrypt_user_key(&user_key)?;
    Ok((UserKey::new(user_key), protected))
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use rand::SeedableRng;

    use super::{HashPurpose, Kdf, MasterKey, make_user_key};
    use crate::{
        EncString, SymmetricCryptoKey,
        keys::{master_key::KdfDerivedKeyMaterial, symmetric_crypto_key::derive_symmetric_key},
    };

    #[test]
    fn test_password_hash_pbkdf2() {
        let password = "asdfasdf";
        let salts = [
            "test@bitwarden.com",
            "TEST@bitwarden.com",
            " test@bitwarden.com",
        ];
        let kdf = Kdf::PBKDF2 {
            iterations: NonZeroU32::new(100_000).unwrap(),
        };

        for salt in salts.iter() {
            let master_key: MasterKey = KdfDerivedKeyMaterial::derive(password, salt, &kdf)
                .unwrap()
                .into();

            assert_eq!(
                "wmyadRMyBZOH7P/a/ucTCbSghKgdzDpPqUnu/DAVtSw=",
                String::from(
                    master_key.derive_master_key_hash(
                        password.as_bytes(),
                        HashPurpose::ServerAuthorization
                    )
                ),
            );
        }
    }

    #[test]
    fn test_password_hash_argon2id() {
        let password = "asdfasdf";
        let salt = "test_salt";
        let kdf = Kdf::Argon2id {
            iterations: NonZeroU32::new(4).unwrap(),
            memory: NonZeroU32::new(32).unwrap(),
            parallelism: NonZeroU32::new(2).unwrap(),
        };

        let master_key: MasterKey = KdfDerivedKeyMaterial::derive(password, salt, &kdf)
            .unwrap()
            .into();

        assert_eq!(
            "PR6UjYmjmppTYcdyTiNbAhPJuQQOmynKbdEl1oyi/iQ=",
            master_key
                .derive_master_key_hash(password.as_bytes(), HashPurpose::ServerAuthorization)
                .to_string(),
        );
    }

    #[test]
    fn test_make_user_key() {
        let mut rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);

        let master_key: MasterKey = KdfDerivedKeyMaterial(Box::pin(
            [
                31, 79, 104, 226, 150, 71, 177, 90, 194, 80, 172, 209, 17, 129, 132, 81, 138, 167,
                69, 167, 254, 149, 2, 27, 39, 197, 64, 42, 22, 195, 86, 75,
            ]
            .into(),
        ))
        .into();

        let (user_key, protected) = make_user_key(&mut rng, &master_key).unwrap();
        let SymmetricCryptoKey::Aes256CbcHmacKey(user_key_unwrapped) = &user_key.0 else {
            panic!("User key is not an Aes256CbcHmacKey");
        };

        assert_eq!(
            user_key_unwrapped.enc_key.as_slice(),
            [
                62, 0, 239, 47, 137, 95, 64, 214, 127, 91, 184, 232, 31, 9, 165, 161, 44, 132, 14,
                195, 206, 154, 127, 59, 24, 27, 225, 136, 239, 113, 26, 30
            ]
        );
        assert_eq!(
            user_key_unwrapped.mac_key.as_slice(),
            [
                152, 76, 225, 114, 185, 33, 111, 65, 159, 68, 83, 103, 69, 109, 86, 25, 49, 74, 66,
                163, 218, 134, 176, 1, 56, 123, 253, 184, 14, 12, 254, 66
            ]
        );

        // Ensure we can decrypt the key and get back the same key
        let decrypted = master_key.decrypt_user_key(protected).unwrap();

        assert_eq!(
            decrypted, user_key.0,
            "Decrypted key doesn't match user key"
        );
    }

    #[test]
    fn test_make_user_key2() {
        let kdf_material = KdfDerivedKeyMaterial(derive_symmetric_key("test1").enc_key.clone());
        let master_key = MasterKey::KdfKey(kdf_material);

        let user_key = SymmetricCryptoKey::Aes256CbcHmacKey(derive_symmetric_key("test2"));

        let encrypted = master_key.encrypt_user_key(&user_key).unwrap();
        let decrypted = master_key.decrypt_user_key(encrypted).unwrap();

        assert_eq!(decrypted, user_key, "Decrypted key doesn't match user key");
    }

    #[test]
    fn test_decrypt_user_key_aes_cbc256_b64() {
        let password = "asdfasdfasdf";
        let salt = "legacy@bitwarden.com";
        let kdf = Kdf::PBKDF2 {
            iterations: NonZeroU32::new(600_000).unwrap(),
        };

        let master_key: MasterKey = KdfDerivedKeyMaterial::derive(password, salt, &kdf)
            .unwrap()
            .into();

        let user_key: EncString = "0.8UClLa8IPE1iZT7chy5wzQ==|6PVfHnVk5S3XqEtQemnM5yb4JodxmPkkWzmDRdfyHtjORmvxqlLX40tBJZ+CKxQWmS8tpEB5w39rbgHg/gqs0haGdZG4cPbywsgGzxZ7uNI=".parse().unwrap();

        let decrypted = master_key.decrypt_user_key(user_key).unwrap();
        let SymmetricCryptoKey::Aes256CbcHmacKey(decrypted) = &decrypted else {
            panic!("Decrypted key is not an Aes256CbcHmacKey");
        };

        assert_eq!(
            decrypted.enc_key.as_slice(),
            [
                12, 95, 151, 203, 37, 4, 236, 67, 137, 97, 90, 58, 6, 127, 242, 28, 209, 168, 125,
                29, 118, 24, 213, 44, 117, 202, 2, 115, 132, 165, 125, 148
            ]
        );
        assert_eq!(
            decrypted.mac_key.as_slice(),
            [
                186, 215, 234, 137, 24, 169, 227, 29, 218, 57, 180, 237, 73, 91, 189, 51, 253, 26,
                17, 52, 226, 4, 134, 75, 194, 208, 178, 133, 128, 224, 140, 167
            ]
        );
    }
}
