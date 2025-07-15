use rsa::{Oaep, RsaPublicKey};
use sha1::Sha1;

use crate::CryptoError;

/// Encrypt data using RSA-OAEP-SHA1 with a 2048 bit key
pub(crate) fn encrypt_rsa2048_oaep_sha1(
    public_key: &RsaPublicKey,
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut rng = rand::thread_rng();

    let padding = Oaep::new::<Sha1>();
    public_key
        .encrypt(&mut rng, padding, data)
        .map_err(|e| CryptoError::RsaError(e.into()))
}
