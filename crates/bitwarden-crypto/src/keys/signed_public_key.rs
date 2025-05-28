//! A public encryption key alone is not authenticated. It needs to be tied to a cryptographic
//! identity, which is provided by a signature keypair. This is done by signing the public key, and
//! requiring consumers to verify the public key before consumption by using unwrap_and_verify.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use super::AsymmetricPublicCryptoKey;
use crate::{
    cose::CoseSerializable, CryptoError, SignedObject, SigningKey, SigningNamespace, VerifyingKey,
};

/// `PublicKeyEncryptionAlgorithm` defines the algorithms used for asymmetric encryption.
/// Currently, only RSA with OAEP and SHA-1 keys are used.
#[derive(Serialize, Deserialize)]
enum PublicKeyEncryptionAlgorithms {
    #[serde(rename = "0")]
    RsaOaepSha1 = 0,
}

/// `PublicKeyFormat` defines the format of the public key in a `SignedAsymmetricPublicKeyMessage`.
/// Currently, only ASN.1 Subject Public Key Info (SPKI) is used, but CoseKey may become another
/// option in the future.
#[derive(Serialize, Deserialize)]
enum PublicKeyFormat {
    #[serde(rename = "0")]
    Spki = 0,
}

/// `SignedAsymmetricPublicKeyMessage` is a message that once signed, makes a claim towards owning a
/// public encryption key.
#[derive(Serialize, Deserialize)]
pub struct SignedPublicKeyMessage {
    /// The algorithm/crypto system used with this public key.
    #[serde(rename = "alg")]
    algorithm: PublicKeyEncryptionAlgorithms,
    /// The format of the public key.
    #[serde(rename = "format")]
    content_format: PublicKeyFormat,
    /// The public key, serialized and formatted in the content format specified in
    /// `content_format`.
    #[serde(rename = "key")]
    public_key: ByteBuf,
}

impl SignedPublicKeyMessage {
    pub fn from_public_key(public_key: &AsymmetricPublicCryptoKey) -> Result<Self, CryptoError> {
        Ok(SignedPublicKeyMessage {
            algorithm: PublicKeyEncryptionAlgorithms::RsaOaepSha1,
            content_format: PublicKeyFormat::Spki,
            public_key: ByteBuf::from(public_key.to_der()?),
        })
    }

    pub fn sign(&self, signing_key: &SigningKey) -> Result<SignedPublicKey, CryptoError> {
        Ok(SignedPublicKey(
            signing_key.sign(self, &SigningNamespace::SignedPublicKey)?,
        ))
    }
}

/// `SignedAsymmetricPublicKey` is a public encryption key, signed by the owner of the encryption
/// keypair. This wrapping ensures that the consumer of the public key MUST verify the identity of
/// the Signer before they can use the public key for encryption.
pub struct SignedPublicKey(pub(crate) SignedObject);

impl TryInto<Vec<u8>> for SignedPublicKey {
    type Error = CryptoError;
    fn try_into(self) -> Result<Vec<u8>, CryptoError> {
        self.0.to_cose()
    }
}

impl TryFrom<Vec<u8>> for SignedPublicKey {
    type Error = CryptoError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, CryptoError> {
        Ok(SignedPublicKey(SignedObject::from_cose(&bytes)?))
    }
}

impl SignedPublicKey {
    pub fn verify_and_unwrap(
        self,
        verifying_key: &VerifyingKey,
    ) -> Result<AsymmetricPublicCryptoKey, CryptoError> {
        let public_key_message: SignedPublicKeyMessage = self
            .0
            .verify_and_unwrap(verifying_key, &SigningNamespace::SignedPublicKey)?;
        match (
            public_key_message.algorithm,
            public_key_message.content_format,
        ) {
            (PublicKeyEncryptionAlgorithms::RsaOaepSha1, PublicKeyFormat::Spki) => Ok(
                AsymmetricPublicCryptoKey::from_der(&public_key_message.public_key.into_vec())
                    .map_err(|_| CryptoError::InvalidKey)?,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AsymmetricCryptoKey, PublicKeyEncryptionAlgorithm, SignatureAlgorithm};

    #[test]
    fn test_signed_asymmetric_public_key() {
        let public_key =
            AsymmetricCryptoKey::make(PublicKeyEncryptionAlgorithm::RsaOaepSha1).to_public_key();
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519).unwrap();
        let message = SignedPublicKeyMessage::from_public_key(&public_key).unwrap();
        let signed_public_key = message.sign(&signing_key).unwrap();
        let verifying_key = signing_key.to_verifying_key();
        let verified_public_key = signed_public_key.verify_and_unwrap(&verifying_key).unwrap();
        assert_eq!(
            public_key.to_der().unwrap(),
            verified_public_key.to_der().unwrap()
        );
    }
}
