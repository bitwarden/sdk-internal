use crate::{
    Result, SymmetricCryptoKey,
    rsa::{RsaKeyPair, make_key_pair},
};

/// User Key
///
/// The User Key is the symmetric encryption key used to decrypt the user's vault.
pub struct UserKey(pub SymmetricCryptoKey);

impl UserKey {
    #[allow(missing_docs)]
    pub fn new(key: SymmetricCryptoKey) -> Self {
        Self(key)
    }

    #[allow(missing_docs)]
    pub fn make_key_pair(&self) -> Result<RsaKeyPair> {
        make_key_pair(&self.0)
    }
}
