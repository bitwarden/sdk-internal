//! # AES operations
//!
//! Contains low level AES operations used by the rest of the library.
//!
//! In most cases you should use the [EncString][crate::EncString] with
//! [KeyEncryptable][crate::KeyEncryptable] & [KeyDecryptable][crate::KeyDecryptable] instead.

use aes::cipher::{
    BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7, inout::InOutBuf,
};
use hmac::{KeyInit, Mac};
use hybrid_array::Array;
use rand::Rng;
use subtle::ConstantTimeEq;
use typenum::U32;

use crate::{
    Aes256CbcHmacKey, CryptoError,
    error::Result,
    util::{PBKDF_SHA256_HMAC_OUT_SIZE, PbkdfSha256Hmac},
};

const AES_BLOCK_SIZE: usize = 16;

/// An aes operation failed either due to invalid padding or due to an invalid MAC.
#[derive(Debug)]
pub(crate) struct DecryptError {}

/// Decrypt using AES-256 in CBC mode.
///
/// Behaves similar to [decrypt_aes256_hmac], but does not validate the MAC.
pub(crate) fn decrypt_aes256(
    iv: &[u8; 16],
    data: Vec<u8>,
    key: &Array<u8, U32>,
) -> Result<Vec<u8>, DecryptError> {
    // Decrypt data
    let mut data = data;
    let decrypted_key_slice = cbc::Decryptor::<aes::Aes256>::new(key, iv.into())
        .decrypt_padded::<Pkcs7>(&mut data)
        .map_err(|_| DecryptError {})?;

    // Data is decrypted in place and returns a subslice of the original Vec, to avoid cloning it,
    // we truncate to the subslice length
    let decrypted_len = decrypted_key_slice.len();
    data.truncate(decrypted_len);

    Ok(data)
}

/// Decrypt using AES-256 in CBC mode with MAC.
///
/// Behaves similar to [decrypt_aes256], but also validates the MAC.
pub(crate) fn decrypt_aes256_hmac(
    iv: &[u8; 16],
    mac: &[u8; 32],
    data: Vec<u8>,
    mac_key: &Array<u8, U32>,
    key: &Array<u8, U32>,
) -> Result<Vec<u8>, DecryptError> {
    let res = generate_mac(mac_key, iv, &data);
    if res.ct_ne(mac).into() {
        return Err(DecryptError {});
    }
    decrypt_aes256(iv, data, key)
}

/// Encrypt using AES-256 in CBC mode with MAC.
///
/// ## Returns
///
/// A Aes256Cbc_HmacSha256_B64 EncString
pub(crate) fn encrypt_aes256_hmac(
    data_dec: &[u8],
    mac_key: &Array<u8, U32>,
    key: &Array<u8, U32>,
) -> Result<([u8; 16], [u8; 32], Vec<u8>)> {
    let rng = rand::rng();
    let (iv, data) = encrypt_aes256_internal(rng, data_dec, key);
    let mac = generate_mac(mac_key, &iv, &data);

    Ok((iv, mac, data))
}

/// Encrypt using AES-256 in CBC mode.
///
/// Used internally by:
/// - [encrypt_aes256_hmac]
fn encrypt_aes256_internal(
    mut rng: impl rand::Rng,
    data_dec: &[u8],
    key: &Array<u8, U32>,
) -> ([u8; 16], Vec<u8>) {
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut iv);
    let data =
        cbc::Encryptor::<aes::Aes256>::new(key, &iv.into()).encrypt_padded_vec::<Pkcs7>(data_dec);

    (iv, data)
}

/// Streaming AES-256-CBC + HMAC-SHA256 decryptor. The HMAC is verified only at
/// [`Self::finalize`]; bytes returned from [`Self::update`] are decrypted but **not yet
/// authenticated** and must be treated as untrusted until `finalize` returns `Ok`.
pub(crate) struct StreamingAes256CbcHmacDecryptor {
    decryptor: cbc::Decryptor<aes::Aes256>,
    hmac: PbkdfSha256Hmac,
    /// Always retains at least one full block so `finalize` can apply PKCS7 unpadding.
    pending: Vec<u8>,
}

impl StreamingAes256CbcHmacDecryptor {
    pub(crate) fn new(iv: &[u8; 16], key: &Aes256CbcHmacKey) -> Self {
        let decryptor = cbc::Decryptor::<aes::Aes256>::new(&key.enc_key, iv.into());
        let mut hmac = PbkdfSha256Hmac::new_from_slice(&key.mac_key)
            .expect("hmac new_from_slice should not fail");
        hmac.update(iv);
        Self {
            decryptor,
            hmac,
            pending: Vec::new(),
        }
    }

    pub(crate) fn update(&mut self, ciphertext_chunk: &[u8]) -> Vec<u8> {
        if ciphertext_chunk.is_empty() {
            return Vec::new();
        }
        self.hmac.update(ciphertext_chunk);
        self.pending.extend_from_slice(ciphertext_chunk);

        // Reserve the final block for `finalize`. Emit only complete blocks beyond that.
        let complete_blocks = self.pending.len() / AES_BLOCK_SIZE;
        let blocks_to_emit = complete_blocks.saturating_sub(1);
        if blocks_to_emit == 0 {
            return Vec::new();
        }

        let bytes_to_emit = blocks_to_emit * AES_BLOCK_SIZE;
        let mut out: Vec<u8> = self.pending.drain(..bytes_to_emit).collect();
        let (chunks, _) = InOutBuf::from(out.as_mut_slice()).into_chunks();
        self.decryptor.decrypt_blocks_inout(chunks);
        out
    }

    pub(crate) fn finalize(mut self, expected_mac: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        let computed: [u8; PBKDF_SHA256_HMAC_OUT_SIZE] = (*self.hmac.finalize().into_bytes())
            .try_into()
            .expect("HMAC output size to be correct");
        if computed.ct_ne(expected_mac).into() {
            return Err(CryptoError::Decrypt);
        }

        if self.pending.is_empty() || !self.pending.len().is_multiple_of(AES_BLOCK_SIZE) {
            return Err(CryptoError::Decrypt);
        }
        let unpadded = self
            .decryptor
            .decrypt_padded::<Pkcs7>(&mut self.pending)
            .map_err(|_| CryptoError::Decrypt)?;
        let unpadded_len = unpadded.len();
        self.pending.truncate(unpadded_len);
        Ok(self.pending)
    }
}

/// Streaming AES-256-CBC + HMAC-SHA256 encryptor. The IV and MAC are returned from
/// [`Self::finalize`].
pub(crate) struct StreamingAes256CbcHmacEncryptor {
    encryptor: cbc::Encryptor<aes::Aes256>,
    hmac: PbkdfSha256Hmac,
    iv: [u8; 16],
    pending: Vec<u8>,
}

pub(crate) struct StreamingEncryptFinal {
    pub iv: [u8; 16],
    pub mac: [u8; 32],
    /// PKCS7 mandates a final padding block even when input is block-aligned, so this is
    /// always at least 16 bytes.
    pub trailing_ciphertext: Vec<u8>,
}

impl StreamingAes256CbcHmacEncryptor {
    pub(crate) fn new(key: &Aes256CbcHmacKey) -> Self {
        let mut iv = [0u8; 16];
        rand::rng().fill_bytes(&mut iv);
        let encryptor = cbc::Encryptor::<aes::Aes256>::new(&key.enc_key, &iv.into());
        let mut hmac = PbkdfSha256Hmac::new_from_slice(&key.mac_key)
            .expect("hmac new_from_slice should not fail");
        hmac.update(&iv);
        Self {
            encryptor,
            hmac,
            iv,
            pending: Vec::new(),
        }
    }

    pub(crate) fn update(&mut self, plaintext_chunk: &[u8]) -> Vec<u8> {
        if plaintext_chunk.is_empty() {
            return Vec::new();
        }
        self.pending.extend_from_slice(plaintext_chunk);

        let complete_blocks = self.pending.len() / AES_BLOCK_SIZE;
        if complete_blocks == 0 {
            return Vec::new();
        }
        let bytes_to_emit = complete_blocks * AES_BLOCK_SIZE;
        let mut out: Vec<u8> = self.pending.drain(..bytes_to_emit).collect();
        let (chunks, _) = InOutBuf::from(out.as_mut_slice()).into_chunks();
        self.encryptor.encrypt_blocks_inout(chunks);
        self.hmac.update(&out);
        out
    }

    pub(crate) fn finalize(mut self) -> StreamingEncryptFinal {
        let trailing = self.encryptor.encrypt_padded_vec::<Pkcs7>(&self.pending);
        self.hmac.update(&trailing);

        let mac: [u8; PBKDF_SHA256_HMAC_OUT_SIZE] = (*self.hmac.finalize().into_bytes())
            .try_into()
            .expect("HMAC output size to be correct");

        StreamingEncryptFinal {
            iv: self.iv,
            mac,
            trailing_ciphertext: trailing,
        }
    }
}

/// Generate a MAC using HMAC-SHA256.
fn generate_mac(mac_key: &[u8], iv: &[u8], data: &[u8]) -> [u8; 32] {
    let mut hmac =
        PbkdfSha256Hmac::new_from_slice(mac_key).expect("hmac new_from_slice should not fail");
    hmac.update(iv);
    hmac.update(data);
    let mac: [u8; PBKDF_SHA256_HMAC_OUT_SIZE] = (*hmac.finalize().into_bytes())
        .try_into()
        // This is safe because Pbkdf2Sha256Hmac output size is always 32 bytes
        .expect("HMAC output size to be correct");
    mac
}

#[cfg(test)]
mod tests {
    use bitwarden_encoding::B64;
    use hybrid_array::ArraySize;
    use rand::SeedableRng;

    use super::*;

    /// Helper function for generating an `Array` of size N with each element being
    /// a multiple of a given increment, starting from a given offset.
    fn generate_array<N: ArraySize>(offset: u8, increment: u8) -> Array<u8, N> {
        Array::from_fn(|i| offset + i as u8 * increment)
    }

    /// Helper function for generating a vector of a given size with each element being
    /// a multiple of a given increment, starting from a given offset.
    fn generate_vec(length: usize, offset: u8, increment: u8) -> Vec<u8> {
        (0..length).map(|i| offset + i as u8 * increment).collect()
    }

    #[test]
    fn test_encrypt_aes256_internal() {
        let key = generate_array(0, 1);

        let rng = rand_chacha::ChaCha8Rng::from_seed([0u8; 32]);
        let result = encrypt_aes256_internal(rng, "EncryptMe!".as_bytes(), &key);
        assert_eq!(
            result,
            (
                [
                    62, 0, 239, 47, 137, 95, 64, 214, 127, 91, 184, 232, 31, 9, 165, 161
                ],
                vec![
                    214, 76, 187, 97, 58, 146, 212, 140, 95, 164, 177, 204, 179, 133, 172, 148
                ]
            )
        );
    }

    #[test]
    fn test_generate_mac() {
        let mac_key = generate_vec(16, 0, 16);

        let iv = generate_vec(16, 0, 16);
        let data = generate_vec(16, 0, 16);

        let mac = generate_mac(&mac_key, &iv, &data);
        assert!(mac.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_decrypt_aes256() {
        let iv = generate_vec(16, 0, 1);
        let iv: &[u8; 16] = iv.as_slice().try_into().unwrap();
        let key = generate_array(0, 1);
        let data: B64 = ("ByUF8vhyX4ddU9gcooznwA==").parse().unwrap();

        let decrypted = decrypt_aes256(iv, data.into(), &key).unwrap();

        assert_eq!(String::from_utf8(decrypted).unwrap(), "EncryptMe!");
    }

    fn streaming_keys() -> (Aes256CbcHmacKey, Array<u8, U32>, Array<u8, U32>) {
        let enc_key = generate_array(0, 1);
        let mac_key = generate_array(0, 2);
        let key = Aes256CbcHmacKey {
            enc_key: Box::pin(enc_key),
            mac_key: Box::pin(mac_key),
        };
        (key, enc_key, mac_key)
    }

    /// Feeds the plaintext through the streaming encryptor in 11-byte chunks (deliberately
    /// not block-aligned), then verifies the produced ciphertext + MAC round-trip through
    /// the bulk `decrypt_aes256_hmac` to the original plaintext.
    #[test]
    fn streaming_encryptor_matches_bulk_decrypt() {
        let (key, enc_key, mac_key) = streaming_keys();
        let plaintext = generate_vec(137, 1, 1);

        let mut enc = StreamingAes256CbcHmacEncryptor::new(&key);
        let mut ciphertext = Vec::new();
        for chunk in plaintext.chunks(11) {
            ciphertext.extend_from_slice(&enc.update(chunk));
        }
        let final_ = enc.finalize();
        ciphertext.extend_from_slice(&final_.trailing_ciphertext);

        let roundtripped =
            decrypt_aes256_hmac(&final_.iv, &final_.mac, ciphertext, &mac_key, &enc_key).unwrap();
        assert_eq!(roundtripped, plaintext);
    }

    /// Encrypts via the bulk path, then decrypts via the streaming decryptor (fed in
    /// 9-byte chunks). Verifies output equals input.
    #[test]
    fn streaming_decryptor_matches_bulk_encrypt() {
        let (key, enc_key, mac_key) = streaming_keys();
        let plaintext = generate_vec(137, 1, 1);

        let (iv, mac, ciphertext) = encrypt_aes256_hmac(&plaintext, &mac_key, &enc_key).unwrap();

        let mut dec = StreamingAes256CbcHmacDecryptor::new(&iv, &key);
        let mut out = Vec::new();
        for chunk in ciphertext.chunks(9) {
            out.extend_from_slice(&dec.update(chunk));
        }
        out.extend_from_slice(&dec.finalize(&mac).unwrap());

        assert_eq!(out, plaintext);
    }

    /// Exercises a block-aligned plaintext length (encryption appends a full PKCS7
    /// padding block, decryptor must strip it).
    #[test]
    fn streaming_roundtrip_block_aligned_input() {
        let (key, _enc_key, _mac_key) = streaming_keys();
        let plaintext = generate_vec(64, 0, 1);

        let mut enc = StreamingAes256CbcHmacEncryptor::new(&key);
        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(&enc.update(&plaintext));
        let final_ = enc.finalize();
        ciphertext.extend_from_slice(&final_.trailing_ciphertext);

        let mut dec = StreamingAes256CbcHmacDecryptor::new(&final_.iv, &key);
        let mut out = Vec::new();
        out.extend_from_slice(&dec.update(&ciphertext));
        out.extend_from_slice(&dec.finalize(&final_.mac).unwrap());

        assert_eq!(out, plaintext);
    }

    /// Empty plaintext round-trips: encryptor still emits a full padding block.
    #[test]
    fn streaming_roundtrip_empty_input() {
        let (key, _enc_key, _mac_key) = streaming_keys();

        let enc = StreamingAes256CbcHmacEncryptor::new(&key);
        let final_ = enc.finalize();
        let ciphertext = final_.trailing_ciphertext;
        assert_eq!(ciphertext.len(), 16);

        let mut dec = StreamingAes256CbcHmacDecryptor::new(&final_.iv, &key);
        let _ = dec.update(&ciphertext);
        let out = dec.finalize(&final_.mac).unwrap();
        assert!(out.is_empty());
    }

    /// HMAC tamper detection: flipping a byte in the MAC must cause `finalize` to fail.
    #[test]
    fn streaming_decryptor_rejects_bad_mac() {
        let (key, enc_key, mac_key) = streaming_keys();
        let plaintext = generate_vec(50, 0, 1);

        let (iv, mut mac, ciphertext) =
            encrypt_aes256_hmac(&plaintext, &mac_key, &enc_key).unwrap();
        mac[0] ^= 0xff;

        let mut dec = StreamingAes256CbcHmacDecryptor::new(&iv, &key);
        let _ = dec.update(&ciphertext);
        let err = dec.finalize(&mac).unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }

    /// Ciphertext tamper detection: flipping a byte in the ciphertext must cause
    /// `finalize` to fail HMAC verification.
    #[test]
    fn streaming_decryptor_rejects_tampered_ciphertext() {
        let (key, enc_key, mac_key) = streaming_keys();
        let plaintext = generate_vec(50, 0, 1);

        let (iv, mac, mut ciphertext) =
            encrypt_aes256_hmac(&plaintext, &mac_key, &enc_key).unwrap();
        ciphertext[3] ^= 0xff;

        let mut dec = StreamingAes256CbcHmacDecryptor::new(&iv, &key);
        let _ = dec.update(&ciphertext);
        let err = dec.finalize(&mac).unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }
}
