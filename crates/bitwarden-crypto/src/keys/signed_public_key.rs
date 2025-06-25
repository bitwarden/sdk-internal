//! A public encryption key alone is not authenticated. It needs to be tied to a cryptographic
//! identity, which is provided by a signature keypair. This is done by signing the public key, and
//! requiring consumers to verify the public key before consumption by using unwrap_and_verify.

use std::str::FromStr;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_repr::{Deserialize_repr, Serialize_repr};

use super::AsymmetricPublicCryptoKey;
use crate::{
    cose::CoseSerializable, error::EncodingError, util::FromStrVisitor, CoseSign1Bytes,
    CryptoError, PublicKeyEncryptionAlgorithm, RawPublicKey, SignedObject, SigningKey,
    SigningNamespace, SpkiPublicKeyBytes, VerifyingKey,
};

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type SignedPublicKey = string;
"#;

/// `PublicKeyFormat` defines the format of the public key in a `SignedAsymmetricPublicKeyMessage`.
/// Currently, only ASN.1 Subject Public Key Info (SPKI) is used, but CoseKey may become another
/// option in the future.
#[derive(Serialize_repr, Deserialize_repr)]
#[repr(u8)]
enum PublicKeyFormat {
    Spki = 0,
}

/// `SignedAsymmetricPublicKeyMessage` is a message that once signed, makes a claim towards owning a
/// public encryption key.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPublicKeyMessage {
    /// The algorithm/crypto system used with this public key.
    algorithm: PublicKeyEncryptionAlgorithm,
    /// The format of the public key.
    content_format: PublicKeyFormat,
    /// The public key, serialized and formatted in the content format specified in
    /// `content_format`.
    ///
    /// Note: [ByteBuf] is used here to ensure efficient serialization. Using [`Vec<u8>`] would
    /// lead to an incompatible encoding of individual bytes, instead of a contiguous byte
    /// buffer.
    public_key: ByteBuf,
}

impl SignedPublicKeyMessage {
    /// Creates a new `SignedPublicKeyMessage` from an `AsymmetricPublicCryptoKey`. This message
    /// can then be signed using a `SigningKey` to create a `SignedPublicKey`.
    pub fn from_public_key(public_key: &AsymmetricPublicCryptoKey) -> Result<Self, CryptoError> {
        match public_key.inner() {
            RawPublicKey::RsaOaepSha1(_) => Ok(SignedPublicKeyMessage {
                algorithm: PublicKeyEncryptionAlgorithm::RsaOaepSha1,
                content_format: PublicKeyFormat::Spki,
                public_key: ByteBuf::from(public_key.to_der()?.as_ref()),
            }),
        }
    }

    /// Signs the `SignedPublicKeyMessage` using the provided `SigningKey`, and returns a
    /// `SignedPublicKey`.
    pub fn sign(&self, signing_key: &SigningKey) -> Result<SignedPublicKey, CryptoError> {
        Ok(SignedPublicKey(
            signing_key.sign(self, &SigningNamespace::SignedPublicKey)?,
        ))
    }
}

/// `SignedAsymmetricPublicKey` is a public encryption key, signed by the owner of the encryption
/// keypair. This wrapping ensures that the consumer of the public key MUST verify the identity of
/// the Signer before they can use the public key for encryption.
#[derive(Clone, Debug)]
pub struct SignedPublicKey(pub(crate) SignedObject);

impl From<SignedPublicKey> for Vec<u8> {
    fn from(val: SignedPublicKey) -> Self {
        val.0.to_cose().to_vec()
    }
}

impl TryFrom<Vec<u8>> for SignedPublicKey {
    type Error = EncodingError;
    fn try_from(bytes: Vec<u8>) -> Result<Self, EncodingError> {
        Ok(SignedPublicKey(SignedObject::from_cose(
            &CoseSign1Bytes::from(bytes),
        )?))
    }
}

impl From<SignedPublicKey> for String {
    fn from(val: SignedPublicKey) -> Self {
        let bytes: Vec<u8> = val.into();
        STANDARD.encode(&bytes)
    }
}

impl SignedPublicKey {
    /// Verifies the signature of the public key against the provided `VerifyingKey`, and returns
    /// the `AsymmetricPublicCryptoKey` if the verification is successful.
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
            (PublicKeyEncryptionAlgorithm::RsaOaepSha1, PublicKeyFormat::Spki) => Ok(
                AsymmetricPublicCryptoKey::from_der(&SpkiPublicKeyBytes::from(
                    public_key_message.public_key.into_vec(),
                ))
                .map_err(|_| EncodingError::InvalidValue("public key"))?,
            ),
        }
    }
}

impl FromStr for SignedPublicKey {
    type Err = EncodingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = STANDARD
            .decode(s)
            .map_err(|_| EncodingError::InvalidCborSerialization)?;
        Self::try_from(bytes)
    }
}

impl<'de> Deserialize<'de> for SignedPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl serde::Serialize for SignedPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let b64_serialized_signed_public_key: String = self.clone().into();
        serializer.serialize_str(&b64_serialized_signed_public_key)
    }
}

impl schemars::JsonSchema for SignedPublicKey {
    fn schema_name() -> String {
        "SignedPublicKey".to_string()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        generator.subschema_for::<String>()
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
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
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
