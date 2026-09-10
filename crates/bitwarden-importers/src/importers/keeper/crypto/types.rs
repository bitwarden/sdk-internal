use std::fmt;

use rand::Rng;

use super::*;

/// AES symmetric key size used by Keeper (256-bit).
pub(crate) const KEEPER_KEY_SIZE: usize = 32;
/// AES-CBC block size / IV size.
pub(crate) const AES_BLOCK_SIZE: usize = 16;
/// AES-GCM nonce size used by Keeper.
pub(crate) const AES_GCM_NONCE_SIZE: usize = 12;
/// AES-GCM authentication tag size.
pub(crate) const AES_GCM_TAG_SIZE: usize = 16;
/// Length of an uncompressed SEC1 P-256 public key (`0x04 || X || Y`).
pub(crate) const EC_PUBLIC_KEY_SIZE: usize = 65;
/// Total length of a valid Keeper `encryptionParams` blob: version(1) + iterations(3) + salt(16) +
/// iv(16) + two 32-byte key blocks(64).
pub(crate) const ENCRYPTION_PARAMS_SIZE: usize = 1 + 3 + 16 + 16 + 64;

/// Keeper record key types, mirroring `RecordKeyType` in Keeper's `record.proto`.
///
/// The numeric values are part of Keeper's wire format and must not change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeeperRecordKeyType {
    /// No key present; cannot be decrypted.
    NoKey = 0,
    /// Encrypted with the data key using AES-CBC ("aes-v1").
    EncryptedByDataKey = 1,
    /// Encrypted with the account's RSA public key (PKCS#1 v1.5). Not supported here.
    EncryptedByPublicKey = 2,
    /// Encrypted with the data key using AES-GCM ("aes-v2").
    EncryptedByDataKeyGcm = 3,
    /// Encrypted with the account's EC public key (ECDH-P256 → AES-GCM).
    EncryptedByPublicKeyEcc = 4,
    /// Encrypted with the root key using AES-CBC. Not supported here.
    EncryptedByRootKeyCbc = 5,
    /// Encrypted with the root key using AES-GCM. Not supported here.
    EncryptedByRootKeyGcm = 6,
}

// Secret types — always zeroized, manually redacted Debug

/// A 256-bit AES symmetric key used throughout Keeper's protocols.
#[derive(Clone)]
pub(crate) struct KeeperAesKey(Zeroizing<[u8; KEEPER_KEY_SIZE]>);

impl KeeperAesKey {
    pub(crate) fn generate() -> Self {
        let mut buf = [0u8; KEEPER_KEY_SIZE];
        bitwarden_random::rng().fill_bytes(&mut buf);
        Self(Zeroizing::new(buf))
    }

    pub(crate) fn from_password(password: &str, salt: &[u8], iterations: u32) -> Self {
        Self(Zeroizing::new(
            pbkdf2_hmac_array::<Sha256, KEEPER_KEY_SIZE>(password.as_bytes(), salt, iterations),
        ))
    }

    pub(crate) fn expose_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<[u8; KEEPER_KEY_SIZE]> for KeeperAesKey {
    fn from(key: [u8; KEEPER_KEY_SIZE]) -> Self {
        Self(Zeroizing::new(key))
    }
}

impl TryFrom<&[u8]> for KeeperAesKey {
    type Error = KeeperCryptoError;

    fn try_from(key: &[u8]) -> Result<Self, KeeperCryptoError> {
        if key.len() != KEEPER_KEY_SIZE {
            return Err(KeeperCryptoError::InvalidKey);
        }
        let mut buf = [0u8; KEEPER_KEY_SIZE];
        buf.copy_from_slice(key);
        Ok(Self(Zeroizing::new(buf)))
    }
}

impl TryFrom<Vec<u8>> for KeeperAesKey {
    type Error = KeeperCryptoError;

    fn try_from(key: Vec<u8>) -> Result<Self, KeeperCryptoError> {
        Self::try_from(key.as_slice())
    }
}

impl fmt::Debug for KeeperAesKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeeperAesKey(REDACTED)")
    }
}

/// EC private key in PKCS#8 DER format — secret material.
#[derive(Clone)]
pub(crate) struct EcPrivateKeyDer(Zeroizing<Vec<u8>>);

impl EcPrivateKeyDer {
    pub(crate) fn expose_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for EcPrivateKeyDer {
    fn from(key: Vec<u8>) -> Self {
        Self(Zeroizing::new(key))
    }
}

impl fmt::Debug for EcPrivateKeyDer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EcPrivateKeyDer(REDACTED)")
    }
}

/// Recovered plaintext from any decrypt operation — secret material, zeroized on drop.
#[derive(Clone)]
pub(crate) struct KeeperPlaintext(Zeroizing<Vec<u8>>);

impl KeeperPlaintext {
    pub(crate) fn expose_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for KeeperPlaintext {
    fn from(pt: Vec<u8>) -> Self {
        Self(Zeroizing::new(pt))
    }
}

impl AsRef<[u8]> for KeeperPlaintext {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for KeeperPlaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeeperPlaintext(REDACTED)")
    }
}

// Non-secret types — derived Debug, safe to print

/// EC public key — uncompressed SEC1 P-256 point, 65 bytes, non-secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EcPublicKey([u8; EC_PUBLIC_KEY_SIZE]);

impl From<[u8; EC_PUBLIC_KEY_SIZE]> for EcPublicKey {
    fn from(key: [u8; EC_PUBLIC_KEY_SIZE]) -> Self {
        Self(key)
    }
}

impl TryFrom<&[u8]> for EcPublicKey {
    type Error = KeeperCryptoError;

    fn try_from(key: &[u8]) -> Result<Self, KeeperCryptoError> {
        if key.len() != EC_PUBLIC_KEY_SIZE {
            return Err(KeeperCryptoError::InvalidKey);
        }
        let mut buf = [0u8; EC_PUBLIC_KEY_SIZE];
        buf.copy_from_slice(key);
        Ok(Self(buf))
    }
}

impl TryFrom<Vec<u8>> for EcPublicKey {
    type Error = KeeperCryptoError;

    fn try_from(key: Vec<u8>) -> Result<Self, KeeperCryptoError> {
        Self::try_from(key.as_slice())
    }
}

impl AsRef<[u8]> for EcPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// AES-CBC encrypted packet: `IV(16) || ciphertext` — non-secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AesV1Packet(Vec<u8>);

impl AesV1Packet {
    pub(crate) fn decrypt(&self, key: &KeeperAesKey) -> Result<KeeperPlaintext, KeeperCryptoError> {
        if self.0.len() < AES_BLOCK_SIZE {
            return Err(KeeperCryptoError::InvalidData);
        }
        let (iv, ciphertext) = self.0.split_at(AES_BLOCK_SIZE);
        let mut buf = ciphertext.to_vec();
        let decrypted = cbc::Decryptor::<aes::Aes256>::new_from_slices(key.expose_bytes(), iv)
            .map_err(|_| KeeperCryptoError::InvalidKey)?
            .decrypt_padded::<Pkcs7>(&mut buf)
            .map_err(|_| KeeperCryptoError::Decryption)?;
        let len = decrypted.len();
        buf.truncate(len);
        Ok(KeeperPlaintext::from(buf))
    }
}

impl From<Vec<u8>> for AesV1Packet {
    fn from(packet: Vec<u8>) -> Self {
        Self(packet)
    }
}

impl AsRef<[u8]> for AesV1Packet {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// AES-GCM encrypted packet: `nonce(12) || ciphertext || tag(16)` — non-secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AesV2Packet(Vec<u8>);

impl AesV2Packet {
    pub(crate) fn encrypt(plaintext: &[u8], key: &KeeperAesKey) -> Result<Self, KeeperCryptoError> {
        let mut nonce = [0u8; AES_GCM_NONCE_SIZE];
        bitwarden_random::rng().fill_bytes(&mut nonce);
        Self::encrypt_with_nonce(plaintext, key, &nonce)
    }

    pub(crate) fn decrypt(&self, key: &KeeperAesKey) -> Result<KeeperPlaintext, KeeperCryptoError> {
        if self.0.len() < AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE {
            return Err(KeeperCryptoError::InvalidData);
        }
        let (nonce_bytes, ciphertext) = self.0.split_at(AES_GCM_NONCE_SIZE);
        let cipher = Aes256Gcm::new_from_slice(key.expose_bytes())
            .map_err(|_| KeeperCryptoError::InvalidKey)?;
        let nonce_arr = Nonce::<<Aes256Gcm as aes_gcm::AeadCore>::NonceSize>::try_from(nonce_bytes)
            .map_err(|_| KeeperCryptoError::InvalidData)?;
        cipher
            .decrypt(&nonce_arr, ciphertext)
            .map(KeeperPlaintext::from)
            .map_err(|_| KeeperCryptoError::Decryption)
    }

    /// Private: used only by `encrypt` (random nonce) and tests (KAT).
    fn encrypt_with_nonce(
        plaintext: &[u8],
        key: &KeeperAesKey,
        nonce: &[u8; AES_GCM_NONCE_SIZE],
    ) -> Result<Self, KeeperCryptoError> {
        let cipher = Aes256Gcm::new_from_slice(key.expose_bytes())
            .map_err(|_| KeeperCryptoError::InvalidKey)?;
        let nonce_arr = Nonce::<<Aes256Gcm as aes_gcm::AeadCore>::NonceSize>::from(*nonce);
        let ciphertext = cipher
            .encrypt(&nonce_arr, plaintext)
            .map_err(|_| KeeperCryptoError::Decryption)?;
        let mut out = Vec::with_capacity(AES_GCM_NONCE_SIZE + ciphertext.len());
        out.extend_from_slice(nonce);
        out.extend_from_slice(&ciphertext);
        Ok(Self(out))
    }

    #[cfg(test)]
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl From<Vec<u8>> for AesV2Packet {
    fn from(packet: Vec<u8>) -> Self {
        Self(packet)
    }
}

impl AsRef<[u8]> for AesV2Packet {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// EC-encrypted packet: `ephemeralPublic(65) || aes-v2 packet` — non-secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EcPacket(Vec<u8>);

impl EcPacket {
    pub(crate) fn encrypt(
        plaintext: &[u8],
        public_key: &EcPublicKey,
    ) -> Result<Self, KeeperCryptoError> {
        let recipient = PublicKey::from_sec1_bytes(public_key.as_ref())
            .map_err(|_| KeeperCryptoError::InvalidKey)?;
        let ephemeral = SecretKey::generate_from_rng(&mut bitwarden_random::rng());
        let encryption_key = derive_ecdh_key(&recipient, &ephemeral);
        let encrypted = AesV2Packet::encrypt(plaintext, &encryption_key)?;
        let ephemeral_public = ephemeral.public_key().to_sec1_point(false);

        let mut out =
            Vec::with_capacity(ephemeral_public.as_bytes().len() + encrypted.as_ref().len());
        out.extend_from_slice(ephemeral_public.as_bytes());
        out.extend_from_slice(encrypted.as_ref());
        Ok(Self(out))
    }

    pub(crate) fn decrypt(
        &self,
        private_key: &EcPrivateKeyDer,
    ) -> Result<KeeperPlaintext, KeeperCryptoError> {
        if self.0.len() < EC_PUBLIC_KEY_SIZE + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE {
            return Err(KeeperCryptoError::InvalidData);
        }
        let secret = SecretKey::from_pkcs8_der(private_key.expose_bytes())
            .map_err(|_| KeeperCryptoError::InvalidKey)?;
        let (ephemeral_bytes, encrypted) = self.0.split_at(EC_PUBLIC_KEY_SIZE);
        let ephemeral_public = PublicKey::from_sec1_bytes(ephemeral_bytes)
            .map_err(|_| KeeperCryptoError::InvalidKey)?;
        let encryption_key = derive_ecdh_key(&ephemeral_public, &secret);
        let packet = AesV2Packet::from(encrypted.to_vec());
        packet.decrypt(&encryption_key)
    }
}

impl From<Vec<u8>> for EcPacket {
    fn from(packet: Vec<u8>) -> Self {
        Self(packet)
    }
}

impl AsRef<[u8]> for EcPacket {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Keeper's encryptionParams blob: `version(1) || iterations(3) || salt(16) || iv(16) || data(64)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EncryptionParamsBlob([u8; ENCRYPTION_PARAMS_SIZE]);

impl EncryptionParamsBlob {
    pub(crate) fn version(&self) -> u8 {
        self.0[0]
    }

    pub(crate) fn iterations(&self) -> u32 {
        (u32::from(self.0[1]) << 16) | (u32::from(self.0[2]) << 8) | u32::from(self.0[3])
    }

    pub(crate) fn salt(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&self.0[4..20]);
        buf
    }

    pub(crate) fn iv(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&self.0[20..36]);
        buf
    }

    pub(crate) fn data(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf.copy_from_slice(&self.0[36..100]);
        buf
    }

    pub(crate) fn decrypt_to_key(&self, password: &str) -> Result<KeeperAesKey, KeeperCryptoError> {
        if self.version() != 1 {
            return Err(KeeperCryptoError::CorruptEncryptionParams);
        }

        let key = KeeperAesKey::from_password(password, &self.salt(), self.iterations());
        let decrypted = decrypt_aes_no_padding(&self.data(), &key, &self.iv())?;
        let bytes = decrypted.expose_bytes();

        let first = &bytes[0..32];
        let second = &bytes[32..64];
        if first.ct_eq(second).unwrap_u8() != 1 {
            return Err(KeeperCryptoError::CorruptEncryptionParams);
        }

        let first_array: [u8; 32] = first
            .try_into()
            .map_err(|_| KeeperCryptoError::CorruptEncryptionParams)?;
        Ok(KeeperAesKey::from(first_array))
    }
}

impl TryFrom<&[u8]> for EncryptionParamsBlob {
    type Error = KeeperCryptoError;

    fn try_from(blob: &[u8]) -> Result<Self, KeeperCryptoError> {
        if blob.first() != Some(&1) {
            return Err(KeeperCryptoError::CorruptEncryptionParams);
        }
        if blob.len() != ENCRYPTION_PARAMS_SIZE {
            return Err(KeeperCryptoError::CorruptEncryptionParams);
        }
        let mut buf = [0u8; ENCRYPTION_PARAMS_SIZE];
        buf.copy_from_slice(blob);
        Ok(Self(buf))
    }
}

impl TryFrom<Vec<u8>> for EncryptionParamsBlob {
    type Error = KeeperCryptoError;

    fn try_from(blob: Vec<u8>) -> Result<Self, KeeperCryptoError> {
        Self::try_from(blob.as_slice())
    }
}

impl AsRef<[u8]> for EncryptionParamsBlob {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Keeper v1 auth hash: SHA-256(derive_key_v1(...)) — transmitted to server, non-secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeeperV1KeyHash([u8; 32]);

impl KeeperV1KeyHash {
    pub(crate) fn from_password(password: &str, salt: &[u8], iterations: u32) -> Self {
        let key = KeeperAesKey::from_password(password, salt, iterations);
        let hash = Sha256::digest(key.expose_bytes());
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&hash);
        Self(buf)
    }
}

impl From<[u8; 32]> for KeeperV1KeyHash {
    fn from(hash: [u8; 32]) -> Self {
        Self(hash)
    }
}

impl AsRef<[u8]> for KeeperV1KeyHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A freshly generated P-256 key pair: PKCS#8 DER private key and uncompressed SEC1 public key.
#[derive(Debug, Clone)]
pub(crate) struct EcKeyPair {
    pub(crate) private_key: EcPrivateKeyDer,
    pub(crate) public_key: EcPublicKey,
}

impl EcKeyPair {
    pub(crate) fn generate() -> Result<Self, KeeperCryptoError> {
        let secret = SecretKey::generate_from_rng(&mut bitwarden_random::rng());
        let private_key_bytes = secret
            .to_pkcs8_der()
            .map_err(|_| KeeperCryptoError::InvalidKey)?
            .as_bytes()
            .to_vec();
        let public_key_bytes = secret.public_key().to_sec1_point(false).as_bytes().to_vec();

        Ok(EcKeyPair {
            private_key: EcPrivateKeyDer::from(private_key_bytes),
            public_key: EcPublicKey::try_from(public_key_bytes)?,
        })
    }
}

/// Typed wrapper for an encrypted record key with its corresponding key type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EncryptedRecordKey {
    EncryptedByDataKey(AesV1Packet),
    EncryptedByDataKeyGcm(AesV2Packet),
}

impl EncryptedRecordKey {
    pub(crate) fn from_wire(
        key_type: KeeperRecordKeyType,
        encrypted_key: Vec<u8>,
    ) -> Result<Self, KeeperCryptoError> {
        match key_type {
            KeeperRecordKeyType::EncryptedByDataKey => {
                Ok(Self::EncryptedByDataKey(AesV1Packet::from(encrypted_key)))
            }
            KeeperRecordKeyType::EncryptedByPublicKey => Err(KeeperCryptoError::UnsupportedKeyType),
            KeeperRecordKeyType::EncryptedByDataKeyGcm => Ok(Self::EncryptedByDataKeyGcm(
                AesV2Packet::from(encrypted_key),
            )),
            KeeperRecordKeyType::EncryptedByPublicKeyEcc => {
                Err(KeeperCryptoError::UnsupportedKeyType)
            }
            KeeperRecordKeyType::NoKey
            | KeeperRecordKeyType::EncryptedByRootKeyCbc
            | KeeperRecordKeyType::EncryptedByRootKeyGcm => {
                Err(KeeperCryptoError::UnsupportedKeyType)
            }
        }
    }

    pub(crate) fn decrypt(
        self,
        data_key: &KeeperAesKey,
    ) -> Result<KeeperPlaintext, KeeperCryptoError> {
        match self {
            Self::EncryptedByDataKey(packet) => packet.decrypt(data_key),
            Self::EncryptedByDataKeyGcm(packet) => packet.decrypt(data_key),
        }
    }
}

// Private helpers

/// Derive Keeper's ECDH content-encryption-key: ECDH(P-256) shared X coordinate, then SHA-256.
fn derive_ecdh_key(public: &PublicKey, secret: &SecretKey) -> KeeperAesKey {
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    let hash = Sha256::digest(shared.raw_secret_bytes());
    let mut buf = [0u8; KEEPER_KEY_SIZE];
    buf.copy_from_slice(&hash);
    KeeperAesKey::from(buf)
}

/// Decrypt 64 bytes of AES-256-CBC ciphertext with no padding.
fn decrypt_aes_no_padding(
    data: &[u8; 64],
    key: &KeeperAesKey,
    iv: &[u8; AES_BLOCK_SIZE],
) -> Result<KeeperPlaintext, KeeperCryptoError> {
    let mut buf = data.to_vec();
    let decrypted = cbc::Decryptor::<aes::Aes256>::new_from_slices(key.expose_bytes(), iv)
        .map_err(|_| KeeperCryptoError::InvalidKey)?
        .decrypt_padded::<NoPadding>(&mut buf)
        .map_err(|_| KeeperCryptoError::Decryption)?;
    let len = decrypted.len();
    buf.truncate(len);
    Ok(KeeperPlaintext::from(buf))
}

#[cfg(test)]
mod tests {
    use super::{
        super::utils::{base64_url_decode, base64_url_encode},
        *,
    };

    const KEEPER_EC_KEY_7: &str =
        "BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM";

    #[test]
    fn aes_v2_round_trip() {
        let key = KeeperAesKey::from([7u8; 32]);
        let plaintext = b"keeper aes-v2 round trip";
        let packet = AesV2Packet::encrypt(plaintext, &key).unwrap();
        // nonce(12) || ciphertext(len) || tag(16)
        assert_eq!(packet.as_ref().len(), 12 + plaintext.len() + 16);
        let decrypted = packet.decrypt(&key).unwrap();
        assert_eq!(decrypted.expose_bytes(), plaintext);
    }

    #[test]
    fn aes_v2_known_answer_empty() {
        // NIST AES-256-GCM KAT: key=0^256, iv=0^96, pt empty => tag
        // 530f8afbc74536b9a963b4f1c4cb738b
        let key = KeeperAesKey::from([0u8; 32]);
        let nonce = [0u8; 12];
        let packet = AesV2Packet::encrypt_with_nonce(&[], &key, &nonce).unwrap();
        let expected = data_encoding::HEXLOWER
            .decode(b"530f8afbc74536b9a963b4f1c4cb738b")
            .unwrap();
        // packet = nonce || (empty ciphertext) || tag
        assert_eq!(&packet.as_ref()[..12], &nonce);
        assert_eq!(&packet.as_ref()[12..], expected.as_slice());
    }

    #[test]
    fn aes_v2_known_answer_block() {
        // NIST AES-256-GCM KAT: key=0^256, iv=0^96, pt=0^128
        //   ct = cea7403d4d606b6e074ec5d3baf39d18, tag = d0d1c8a799996bf0265b98b5d48ab919
        let key = KeeperAesKey::from([0u8; 32]);
        let nonce = [0u8; 12];
        let packet = AesV2Packet::encrypt_with_nonce(&[0u8; 16], &key, &nonce).unwrap();
        let expected_ct = data_encoding::HEXLOWER
            .decode(b"cea7403d4d606b6e074ec5d3baf39d18")
            .unwrap();
        let expected_tag = data_encoding::HEXLOWER
            .decode(b"d0d1c8a799996bf0265b98b5d48ab919")
            .unwrap();
        assert_eq!(&packet.as_ref()[12..28], expected_ct.as_slice());
        assert_eq!(&packet.as_ref()[28..], expected_tag.as_slice());
    }

    #[test]
    fn aes_v2_rejects_tampered_ciphertext() {
        let key = KeeperAesKey::from([3u8; 32]);
        let mut packet = AesV2Packet::encrypt(b"secret", &key).unwrap();
        // Flip a bit in the tag region.
        let last = packet.as_mut_slice().len() - 1;
        packet.as_mut_slice()[last] ^= 0x01;
        assert!(matches!(
            packet.decrypt(&key),
            Err(KeeperCryptoError::Decryption)
        ));
    }

    #[test]
    fn keeper_aes_key_rejects_wrong_size() {
        assert!(matches!(
            KeeperAesKey::try_from([0u8; 16].as_slice()),
            Err(KeeperCryptoError::InvalidKey)
        ));
        assert!(matches!(
            KeeperAesKey::try_from([0u8; 31].as_slice()),
            Err(KeeperCryptoError::InvalidKey)
        ));
    }

    #[test]
    fn aes_v1_round_trip() {
        // Produce a valid aes-v1 packet (IV || AES-256-CBC/PKCS7) and decrypt it.
        use aes::cipher::BlockModeEncrypt;
        let key = KeeperAesKey::from([9u8; 32]);
        let iv = [1u8; 16];
        let plaintext = b"keeper aes-v1 unauthenticated payload";
        let ciphertext = cbc::Encryptor::<aes::Aes256>::new_from_slices(key.expose_bytes(), &iv)
            .unwrap()
            .encrypt_padded_vec::<Pkcs7>(plaintext);
        let mut packet_bytes = iv.to_vec();
        packet_bytes.extend_from_slice(&ciphertext);

        let packet = AesV1Packet::from(packet_bytes);
        let decrypted = packet.decrypt(&key).unwrap();
        assert_eq!(decrypted.expose_bytes(), plaintext);
    }

    #[test]
    fn pbkdf2_known_answer() {
        // PBKDF2-HMAC-SHA256, password="password", salt="salt", c=1, dkLen=32
        let key = KeeperAesKey::from_password("password", b"salt", 1);
        let expected = data_encoding::HEXLOWER
            .decode(b"120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
            .unwrap();
        assert_eq!(key.expose_bytes(), expected.as_slice());
    }

    #[test]
    fn derive_v1_key_hash_is_sha256_of_key() {
        let key = KeeperAesKey::from_password("hunter2", b"somesalt", 1000);
        let expected = Sha256::digest(key.expose_bytes()).to_vec();
        let hash = KeeperV1KeyHash::from_password("hunter2", b"somesalt", 1000);
        assert_eq!(hash.as_ref(), expected.as_slice());
    }

    #[test]
    fn base64_url_round_trip_and_keeper_keys() {
        let bytes = [0xfb, 0xff, 0x00, 0x10, 0x3e, 0x7d];
        let encoded = base64_url_encode(&bytes);
        // URL-safe, unpadded.
        assert!(!encoded.contains('+') && !encoded.contains('/') && !encoded.contains('='));
        assert_eq!(base64_url_decode(&encoded).unwrap(), bytes);

        // A real Keeper EC key decodes to a 65-byte uncompressed point.
        let ec = base64_url_decode(KEEPER_EC_KEY_7).unwrap();
        assert_eq!(ec.len(), 65);
        assert_eq!(ec[0], 0x04);

        // Tolerates trailing padding.
        assert_eq!(base64_url_decode("YWJj").unwrap(), b"abc");
        assert_eq!(base64_url_decode("YWJj==").unwrap(), b"abc");
    }

    #[test]
    fn ec_round_trip() {
        let pair = EcKeyPair::generate().unwrap();
        assert_eq!(pair.public_key.as_ref()[0], 0x04);

        let plaintext = b"an ec-protected record key";
        let packet = EcPacket::encrypt(plaintext, &pair.public_key).unwrap();
        // ephemeral public(65) || nonce(12) || ct || tag(16)
        assert_eq!(packet.as_ref().len(), 65 + 12 + plaintext.len() + 16);
        let decrypted = packet.decrypt(&pair.private_key).unwrap();
        assert_eq!(decrypted.expose_bytes(), plaintext);
    }

    #[test]
    fn ec_rejects_wrong_private_key() {
        let pair = EcKeyPair::generate().unwrap();
        let other = EcKeyPair::generate().unwrap();
        let packet = EcPacket::encrypt(b"secret", &pair.public_key).unwrap();
        assert!(packet.decrypt(&other.private_key).is_err());
    }

    /// Build a valid `encryptionParams` blob the way Keeper would, so we can test decryption.
    fn make_encryption_params(
        password: &str,
        iterations: u32,
        salt: &[u8; 16],
        data_key: &[u8; 32],
    ) -> Vec<u8> {
        use aes::cipher::BlockModeEncrypt;
        let derived = KeeperAesKey::from_password(password, salt, iterations);
        let iv = [0x42u8; 16];
        // Two identical 32-byte blocks, AES-CBC no padding.
        let mut blocks = data_key.to_vec();
        blocks.extend_from_slice(data_key);
        let encrypted = cbc::Encryptor::<aes::Aes256>::new_from_slices(derived.expose_bytes(), &iv)
            .unwrap()
            .encrypt_padded_vec::<NoPadding>(&blocks);

        let mut params = vec![
            1u8, // version
            (iterations >> 16) as u8,
            (iterations >> 8) as u8,
            iterations as u8,
        ];
        params.extend_from_slice(salt);
        params.extend_from_slice(&iv);
        params.extend_from_slice(&encrypted);
        params
    }

    #[test]
    fn decrypt_encryption_params_recovers_data_key() {
        let data_key = [0x11u8; 32];
        let params_bytes =
            make_encryption_params("master-password", 1000, &[0x07u8; 16], &data_key);
        let params = EncryptionParamsBlob::try_from(params_bytes.as_slice()).unwrap();
        let recovered = params.decrypt_to_key("master-password").unwrap();
        assert_eq!(recovered.expose_bytes(), &data_key);
    }

    #[test]
    fn decrypt_encryption_params_rejects_wrong_password() {
        let data_key = [0x11u8; 32];
        let params_bytes =
            make_encryption_params("master-password", 1000, &[0x07u8; 16], &data_key);
        let params = EncryptionParamsBlob::try_from(params_bytes.as_slice()).unwrap();
        // Wrong password yields mismatched blocks -> CorruptEncryptionParams.
        assert!(matches!(
            params.decrypt_to_key("wrong-password"),
            Err(KeeperCryptoError::CorruptEncryptionParams)
        ));
    }

    #[test]
    fn encryption_params_blob_rejects_bad_version() {
        let mut params = make_encryption_params("pw", 100, &[0u8; 16], &[0u8; 32]);
        params[0] = 2;
        assert!(matches!(
            EncryptionParamsBlob::try_from(params.as_slice()),
            Err(KeeperCryptoError::CorruptEncryptionParams)
        ));
    }

    #[test]
    fn encryption_params_blob_rejects_bad_length() {
        assert!(matches!(
            EncryptionParamsBlob::try_from(&[1u8, 0, 0, 1][..]),
            Err(KeeperCryptoError::CorruptEncryptionParams)
        ));
    }

    #[test]
    fn decrypt_keeper_key_dispatches() {
        let data_key = KeeperAesKey::from([5u8; 32]);
        let record_key = [0xABu8; 32];

        // aes-v2 path
        let packet = AesV2Packet::encrypt(&record_key, &data_key).unwrap();
        let record_key_typed = EncryptedRecordKey::EncryptedByDataKeyGcm(packet);
        let decrypted = record_key_typed.decrypt(&data_key).unwrap();
        assert_eq!(decrypted.expose_bytes(), &record_key);

        // aes-v1 path
        use aes::cipher::BlockModeEncrypt;
        let iv = [2u8; 16];
        let ct = cbc::Encryptor::<aes::Aes256>::new_from_slices(data_key.expose_bytes(), &iv)
            .unwrap()
            .encrypt_padded_vec::<Pkcs7>(&record_key);
        let mut v1_packet_bytes = iv.to_vec();
        v1_packet_bytes.extend_from_slice(&ct);
        let v1_packet = AesV1Packet::from(v1_packet_bytes);
        let record_key_typed = EncryptedRecordKey::EncryptedByDataKey(v1_packet);
        let decrypted = record_key_typed.decrypt(&data_key).unwrap();
        assert_eq!(decrypted.expose_bytes(), &record_key);
    }

    #[test]
    fn encrypted_record_key_from_wire_rejects_unsupported_types() {
        assert!(matches!(
            EncryptedRecordKey::from_wire(KeeperRecordKeyType::NoKey, vec![]),
            Err(KeeperCryptoError::UnsupportedKeyType)
        ));
        assert!(matches!(
            EncryptedRecordKey::from_wire(KeeperRecordKeyType::EncryptedByRootKeyGcm, vec![]),
            Err(KeeperCryptoError::UnsupportedKeyType)
        ));
    }

    // All vectors below are source from an actual Keeper server interaction

    #[test]
    fn test_decrypt_aes_v1_packet() {
        let key_material = [
            203, 103, 215, 14, 117, 67, 191, 159, 245, 249, 129, 244, 129, 225, 152, 136, 122, 180,
            100, 87, 141, 245, 21, 161, 34, 241, 216, 22, 152, 191, 215, 4,
        ];
        let key: KeeperAesKey = KeeperAesKey::from(key_material);
        let packet_data = vec![
            232, 153, 119, 221, 36, 178, 6, 39, 49, 114, 76, 97, 164, 181, 217, 40, 224, 137, 235,
            105, 8, 103, 53, 36, 34, 166, 18, 163, 253, 134, 224, 15, 95, 133, 78, 200, 19, 172,
            118, 95, 79, 158, 115, 47, 133, 131, 66, 1, 110, 21, 85, 80, 134, 161, 150, 173, 150,
            47, 195, 118, 14, 108, 134, 134,
        ];
        let packet = AesV1Packet::from(packet_data);
        let expected_result = [
            178, 244, 197, 56, 159, 204, 154, 118, 68, 191, 72, 149, 213, 226, 182, 44, 96, 138,
            224, 51, 116, 239, 74, 23, 180, 143, 39, 215, 74, 33, 34, 119,
        ];
        assert_eq!(
            packet.decrypt(&key).unwrap().expose_bytes(),
            &expected_result
        );
    }

    #[test]
    fn test_decrypt_aes_v2_packet() {
        let key_material = [
            87, 239, 233, 9, 250, 196, 218, 62, 252, 156, 245, 5, 0, 41, 105, 25, 14, 89, 206, 93,
            98, 40, 241, 170, 15, 248, 109, 230, 75, 71, 89, 66,
        ];
        let key: KeeperAesKey = KeeperAesKey::from(key_material);
        let packet_data = vec![
            210, 217, 108, 57, 214, 26, 57, 169, 167, 32, 35, 126, 123, 1, 81, 136, 3, 19, 146,
            191, 37, 84, 155, 184, 226, 8, 89, 52, 239, 159, 9, 169, 10, 223, 117, 246, 57, 241,
            129, 196, 245, 199, 255, 160, 65, 85, 94, 149, 7, 225, 128, 94, 58, 229, 124, 103, 171,
            100, 71, 137, 59, 103, 10, 42,
        ];
        let packet = AesV2Packet::from(packet_data);
        let expected_result = [
            10, 34, 20, 213, 192, 224, 166, 48, 150, 152, 32, 196, 13, 155, 89, 15, 143, 36, 30,
            185, 165, 116, 206, 78, 176, 52, 96, 91, 212, 247, 207, 98, 7, 152, 253, 110,
        ];
        assert_eq!(
            packet.decrypt(&key).unwrap().expose_bytes(),
            &expected_result
        );
    }

    #[test]
    fn test_decrypt_encryption_params_blob_to_key() {
        // Test account used. First created and later removed
        let password = "not_a_real_cred_123";
        let params_blob_data: [u8; ENCRYPTION_PARAMS_SIZE] = [
            1, 15, 66, 64, 221, 59, 249, 48, 17, 39, 135, 170, 169, 247, 161, 3, 241, 7, 33, 96,
            127, 95, 102, 162, 81, 252, 193, 108, 240, 76, 109, 247, 7, 151, 138, 210, 107, 222,
            17, 227, 20, 50, 230, 71, 97, 45, 93, 230, 80, 18, 212, 225, 195, 95, 182, 194, 167,
            193, 200, 151, 87, 104, 63, 18, 255, 56, 17, 217, 165, 38, 129, 21, 236, 111, 119, 26,
            233, 107, 167, 13, 212, 207, 66, 26, 195, 157, 179, 173, 37, 82, 216, 232, 61, 164,
            154, 164, 203, 64, 122, 114,
        ];
        let params_blob = EncryptionParamsBlob::try_from(&params_blob_data[..]).unwrap();
        let key = params_blob.decrypt_to_key(password).unwrap();
        let expected_key = [
            34, 173, 124, 22, 118, 177, 128, 33, 207, 244, 224, 27, 139, 137, 231, 199, 25, 1, 95,
            53, 65, 156, 214, 243, 86, 230, 203, 95, 138, 183, 10, 119,
        ];
        assert_eq!(key.expose_bytes(), &expected_key);
    }

    #[test]
    fn test_decrypt_ec_packet() {
        let key_material = vec![
            48, 129, 135, 2, 1, 0, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72,
            206, 61, 3, 1, 7, 4, 109, 48, 107, 2, 1, 1, 4, 32, 79, 213, 137, 234, 131, 184, 48,
            217, 70, 58, 75, 139, 51, 52, 102, 97, 153, 213, 19, 105, 237, 120, 219, 138, 82, 196,
            185, 20, 188, 149, 50, 61, 161, 68, 3, 66, 0, 4, 115, 150, 224, 101, 182, 185, 214, 7,
            31, 212, 3, 223, 179, 211, 46, 75, 89, 52, 204, 212, 145, 153, 100, 18, 152, 156, 64,
            58, 71, 5, 183, 206, 31, 190, 143, 60, 42, 110, 223, 196, 69, 173, 9, 72, 117, 217, 57,
            223, 251, 250, 157, 187, 94, 210, 38, 230, 177, 230, 121, 182, 139, 188, 29, 149,
        ];
        let key: EcPrivateKeyDer = EcPrivateKeyDer::from(key_material);
        let packet_data = vec![
            4, 41, 184, 168, 237, 26, 164, 49, 255, 155, 95, 64, 167, 83, 140, 204, 220, 15, 61,
            126, 26, 204, 83, 20, 15, 200, 178, 204, 219, 209, 244, 40, 152, 166, 103, 239, 98,
            107, 103, 36, 84, 235, 163, 105, 208, 62, 107, 75, 206, 201, 74, 21, 139, 235, 144,
            117, 136, 235, 74, 185, 30, 51, 227, 84, 104, 0, 254, 220, 127, 107, 233, 3, 210, 101,
            189, 164, 238, 178, 150, 8, 232, 235, 57, 108, 235, 169, 128, 43, 5, 78, 137, 34, 37,
            3, 80, 56, 117, 5, 96, 106, 248, 172, 52, 204, 127, 235, 114, 17, 152, 249, 207, 83,
            181, 95, 85, 16, 210, 179, 191, 145, 251, 36, 74, 121, 183,
        ];
        let packet = EcPacket::from(packet_data);
        let expected_result = [
            47, 188, 81, 85, 137, 199, 133, 148, 5, 227, 0, 214, 49, 37, 80, 0, 184, 111, 147, 2,
            174, 200, 145, 206, 78, 151, 178, 151, 54, 205, 55, 240,
        ];
        assert_eq!(
            packet.decrypt(&key).unwrap().expose_bytes(),
            &expected_result
        );
    }

    #[test]
    fn test_aes_key_encryption() {
        let key: KeeperAesKey = KeeperAesKey::generate();
        let data = String::from("This is a test");
        let packet =
            AesV2Packet::encrypt(data.as_bytes(), &key).expect("Could not AES encrypt data");
        assert_eq!(
            packet.decrypt(&key).unwrap().expose_bytes(),
            data.as_bytes()
        );
    }

    #[test]
    fn test_ec_key_encryption() {
        let key_pair: EcKeyPair = EcKeyPair::generate().unwrap();
        let data = String::from("This is a test");
        let packet = EcPacket::encrypt(data.as_bytes(), &key_pair.public_key).unwrap();
        assert_eq!(
            packet
                .decrypt(&key_pair.private_key)
                .unwrap()
                .expose_bytes(),
            data.as_bytes()
        );
    }

    #[test]
    fn test_decrypt_aes_no_padding() {
        let key_material = [
            130, 48, 91, 133, 175, 167, 244, 40, 222, 240, 200, 102, 29, 55, 207, 150, 67, 255, 26,
            193, 195, 52, 124, 207, 93, 174, 215, 199, 31, 89, 214, 116,
        ];
        let key: KeeperAesKey = KeeperAesKey::from(key_material);
        let packet_data: [u8; 64] = [
            35, 134, 106, 75, 43, 29, 90, 89, 253, 251, 148, 108, 25, 233, 150, 39, 239, 33, 136,
            26, 163, 100, 214, 82, 240, 196, 28, 221, 120, 74, 66, 248, 197, 59, 24, 14, 60, 180,
            25, 160, 234, 13, 210, 174, 131, 22, 201, 9, 111, 203, 226, 24, 109, 170, 185, 120, 85,
            44, 142, 198, 190, 198, 236, 197,
        ];
        let iv: [u8; 16] = [
            48, 147, 214, 245, 143, 93, 92, 192, 102, 52, 224, 166, 171, 143, 235, 99,
        ];

        let plain_text = decrypt_aes_no_padding(&packet_data, &key, &iv);
        let expected_result = [
            203, 103, 215, 14, 117, 67, 191, 159, 245, 249, 129, 244, 129, 225, 152, 136, 122, 180,
            100, 87, 141, 245, 21, 161, 34, 241, 216, 22, 152, 191, 215, 4, 203, 103, 215, 14, 117,
            67, 191, 159, 245, 249, 129, 244, 129, 225, 152, 136, 122, 180, 100, 87, 141, 245, 21,
            161, 34, 241, 216, 22, 152, 191, 215, 4,
        ];
        assert_eq!(plain_text.unwrap().expose_bytes(), &expected_result);
    }
}
