//! RSA with OAEP padding.

use zeroize::Zeroizing;

use crate::{Error, backend};

/// Hash used for OAEP and MGF1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OaepHash {
    /// SHA-1. Legacy use only.
    Sha1,
    /// SHA-256.
    Sha256,
}

/// Modulus size for key generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySize {
    /// 2048-bit modulus.
    Rsa2048,
}

/// Big-endian, minimal-length private key components. Secret parts are zeroized on drop.
pub struct PrivateComponents {
    /// Modulus.
    pub n: Vec<u8>,
    /// Public exponent.
    pub e: Vec<u8>,
    /// Private exponent.
    pub d: Zeroizing<Vec<u8>>,
    /// First prime.
    pub p: Zeroizing<Vec<u8>>,
    /// Second prime.
    pub q: Zeroizing<Vec<u8>>,
    /// CRT coefficient `q^-1 mod p`.
    pub iqmp: Zeroizing<Vec<u8>>,
}

/// RSA private key.
#[derive(Clone)]
pub struct PrivateKey(backend::rsa::PrivateKey);

impl zeroize::ZeroizeOnDrop for PrivateKey where backend::rsa::PrivateKey: zeroize::ZeroizeOnDrop {}

impl PrivateKey {
    /// Generates a fresh key.
    pub fn generate(size: KeySize) -> Self {
        Self(backend::rsa::PrivateKey::generate(size))
    }

    /// Parses a PKCS#8 `PrivateKeyInfo`.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        backend::rsa::PrivateKey::from_pkcs8_der(der).map(Self)
    }

    /// Parses a PEM-armored PKCS#8 `PrivateKeyInfo` (`-----BEGIN PRIVATE KEY-----`).
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Error> {
        backend::rsa::PrivateKey::from_pkcs8_pem(pem).map(Self)
    }

    /// Parses a PKCS#1 `RSAPrivateKey`.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, Error> {
        backend::rsa::PrivateKey::from_pkcs1_der(der).map(Self)
    }

    /// Builds a two-prime key from big-endian components and validates it. `primes` must hold
    /// exactly `p` and `q`.
    pub fn from_components(n: &[u8], e: &[u8], d: &[u8], primes: &[&[u8]]) -> Result<Self, Error> {
        backend::rsa::PrivateKey::from_components(n, e, d, primes).map(Self)
    }

    /// Serializes as PKCS#8 `PrivateKeyInfo`.
    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.0.to_pkcs8_der()
    }

    /// Returns the key components.
    pub fn components(&self) -> PrivateComponents {
        self.0.components()
    }

    /// Returns the matching public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }

    /// RSAES-OAEP decryption with an empty label.
    pub fn decrypt_oaep(
        &self,
        hash: OaepHash,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.0.decrypt_oaep(hash, ciphertext)
    }
}

/// RSA public key.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(backend::rsa::PublicKey);

impl PublicKey {
    /// Parses a `SubjectPublicKeyInfo`.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        backend::rsa::PublicKey::from_spki_der(der).map(Self)
    }

    /// Serializes as `SubjectPublicKeyInfo`.
    pub fn to_spki_der(&self) -> Result<Vec<u8>, Error> {
        self.0.to_spki_der()
    }

    /// Big-endian, minimal-length modulus `n`.
    pub fn modulus(&self) -> Vec<u8> {
        self.0.modulus()
    }

    /// Big-endian, minimal-length public exponent `e`.
    pub fn exponent(&self) -> Vec<u8> {
        self.0.exponent()
    }

    /// Modulus length in bytes.
    pub fn modulus_len(&self) -> usize {
        self.0.modulus_len()
    }

    /// RSAES-OAEP encryption with an empty label.
    pub fn encrypt_oaep(&self, hash: OaepHash, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.encrypt_oaep(hash, plaintext)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use bitwarden_encoding::B64;

    use super::*;

    static KEY: LazyLock<PrivateKey> = LazyLock::new(|| PrivateKey::generate(KeySize::Rsa2048));

    #[test]
    fn oaep_roundtrip() {
        let public = KEY.public_key();
        assert_eq!(public.modulus_len(), 256);

        for hash in [OaepHash::Sha1, OaepHash::Sha256] {
            let ct = public.encrypt_oaep(hash, b"secret").expect("fits");
            assert_eq!(
                KEY.decrypt_oaep(hash, &ct).expect("valid").as_slice(),
                b"secret"
            );
        }
    }

    #[test]
    fn oaep_hash_mismatch_fails() {
        let ct = KEY
            .public_key()
            .encrypt_oaep(OaepHash::Sha1, b"secret")
            .expect("fits");
        assert_eq!(
            KEY.decrypt_oaep(OaepHash::Sha256, &ct).err(),
            Some(Error::DecryptionFailed)
        );
    }

    #[test]
    fn der_roundtrips() {
        let der = KEY.to_pkcs8_der().expect("encodes");
        let parsed = PrivateKey::from_pkcs8_der(&der).expect("parses");
        assert!(parsed.public_key() == KEY.public_key());

        let spki = KEY.public_key().to_spki_der().expect("encodes");
        assert!(PublicKey::from_spki_der(&spki).expect("parses") == KEY.public_key());

        assert_eq!(
            PrivateKey::from_pkcs8_der(b"junk").err(),
            Some(Error::InvalidKey)
        );
    }

    /// 48 raw bytes encode to one 64-character PEM line (RFC 7468).
    const PEM_LINE_BYTES: usize = 48;

    #[test]
    fn pem_parses() {
        let der = KEY.to_pkcs8_der().expect("encodes");
        let body = der
            .chunks(PEM_LINE_BYTES)
            .map(|line| B64::from(line).to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n");

        let parsed = PrivateKey::from_pkcs8_pem(&pem).expect("parses");
        assert!(parsed.public_key() == KEY.public_key());
        assert_eq!(
            PrivateKey::from_pkcs8_pem("junk").err(),
            Some(Error::InvalidKey)
        );
    }

    #[test]
    fn components_roundtrip() {
        let c = KEY.components();
        assert_eq!(c.e, vec![0x01, 0x00, 0x01]);
        assert_eq!(c.n, KEY.public_key().modulus());

        let rebuilt = PrivateKey::from_components(&c.n, &c.e, &c.d, &[&c.p, &c.q]).expect("valid");
        assert!(rebuilt.public_key() == KEY.public_key());
    }
}
