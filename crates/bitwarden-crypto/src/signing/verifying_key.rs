//! A verifying key is the public part of a signature key pair. It is used to verify signatures.
//!
//! This implements the lowest layer of the signature module, verifying signatures on raw byte
//! arrays.

use ciborium::{Value, value::Integer};
use coset::{
    CborSerializable, RegisteredLabel, RegisteredLabelWithPrivate,
    iana::{Algorithm, EllipticCurve, EnumI64, KeyOperation, KeyType, OkpKeyParameter},
};

use super::{SignatureAlgorithm, ed25519_verifying_key, key_id};
use crate::{
    CoseKeyBytes, CryptoError,
    content_format::CoseKeyContentFormat,
    cose::CoseSerializable,
    error::{EncodingError, SignatureError},
    keys::KeyId,
};

/// A `VerifyingKey` without the key id. This enum contains a variant for each supported signature
/// scheme.
pub(super) enum RawVerifyingKey {
    Ed25519(ed25519_dalek::VerifyingKey),
}

/// A verifying key is a public key used for verifying signatures. It can be published to other
/// users, who can use it to verify that messages were signed by the holder of the corresponding
/// `SigningKey`.
pub struct VerifyingKey {
    pub(super) id: KeyId,
    pub(super) inner: RawVerifyingKey,
}

impl VerifyingKey {
    /// Returns the signature scheme used by the verifying key.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        match &self.inner {
            RawVerifyingKey::Ed25519(_) => SignatureAlgorithm::Ed25519,
        }
    }

    /// Verifies the signature of the given data, for the given namespace.
    /// This should never be used directly, but only through the `verify` method, to enforce
    /// strong domain separation of the signatures.
    pub(super) fn verify_raw(&self, signature: &[u8], data: &[u8]) -> Result<(), CryptoError> {
        match &self.inner {
            RawVerifyingKey::Ed25519(key) => {
                let sig = ed25519_dalek::Signature::from_bytes(
                    signature
                        .try_into()
                        .map_err(|_| SignatureError::InvalidSignature)?,
                );
                key.verify_strict(data, &sig)
                    .map_err(|_| SignatureError::InvalidSignature.into())
            }
        }
    }
}

impl CoseSerializable<CoseKeyContentFormat> for VerifyingKey {
    fn to_cose(&self) -> CoseKeyBytes {
        match &self.inner {
            RawVerifyingKey::Ed25519(key) => coset::CoseKeyBuilder::new_okp_key()
                .key_id((&self.id).into())
                .algorithm(Algorithm::EdDSA)
                .param(
                    OkpKeyParameter::Crv.to_i64(), // Elliptic curve identifier
                    Value::Integer(Integer::from(EllipticCurve::Ed25519.to_i64())),
                )
                // Note: X does not refer to the X coordinate of the public key curve point, but
                // to the verifying key (signature public key), as represented by the curve spec. In
                // the case of Ed25519, this is the compressed Y coordinate. This
                // was ill-defined in earlier drafts of the standard. https://www.rfc-editor.org/rfc/rfc9053.html#name-octet-key-pair
                .param(
                    OkpKeyParameter::X.to_i64(), // Verifying key (digital signature public key)
                    Value::Bytes(key.to_bytes().to_vec()),
                )
                .add_key_op(KeyOperation::Verify)
                .build()
                .to_vec()
                .expect("Verifying key is always serializable")
                .into(),
        }
    }

    fn from_cose(bytes: &CoseKeyBytes) -> Result<Self, EncodingError>
    where
        Self: Sized,
    {
        let cose_key = coset::CoseKey::from_slice(bytes.as_ref())
            .map_err(|_| EncodingError::InvalidCoseEncoding)?;

        let algorithm = cose_key
            .alg
            .as_ref()
            .ok_or(EncodingError::MissingValue("COSE key algorithm"))?;
        match (&cose_key.kty, algorithm) {
            (
                RegisteredLabel::Assigned(KeyType::OKP),
                RegisteredLabelWithPrivate::Assigned(Algorithm::EdDSA),
            ) => Ok(VerifyingKey {
                id: key_id(&cose_key)?,
                inner: RawVerifyingKey::Ed25519(ed25519_verifying_key(&cose_key)?),
            }),
            _ => Err(EncodingError::UnsupportedValue(
                "COSE key type or algorithm",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERIFYING_KEY: &[u8] = &[
        166, 1, 1, 2, 80, 55, 131, 40, 191, 230, 137, 76, 182, 184, 139, 94, 152, 45, 63, 13, 71,
        3, 39, 4, 129, 2, 32, 6, 33, 88, 32, 93, 213, 35, 177, 81, 219, 226, 241, 147, 140, 238,
        32, 34, 183, 213, 107, 227, 92, 75, 84, 208, 47, 198, 80, 18, 188, 172, 145, 184, 154, 26,
        170,
    ];
    const SIGNED_DATA_RAW: &[u8] = &[
        247, 239, 74, 181, 75, 54, 137, 225, 2, 158, 14, 0, 61, 210, 254, 208, 255, 16, 8, 81, 173,
        33, 59, 67, 204, 31, 45, 38, 147, 118, 228, 84, 235, 252, 104, 38, 194, 173, 62, 52, 9,
        184, 1, 22, 113, 134, 154, 108, 24, 83, 78, 2, 23, 235, 80, 22, 57, 110, 100, 24, 151, 33,
        186, 12,
    ];

    #[test]
    fn test_cose_roundtrip_encode_verifying() {
        let verifying_key = VerifyingKey::from_cose(&CoseKeyBytes::from(VERIFYING_KEY)).unwrap();
        let cose = verifying_key.to_cose();
        let parsed_key = VerifyingKey::from_cose(&cose).unwrap();

        assert_eq!(verifying_key.to_cose(), parsed_key.to_cose());
    }

    #[test]
    fn test_testvector() {
        let verifying_key = VerifyingKey::from_cose(&CoseKeyBytes::from(VERIFYING_KEY)).unwrap();
        assert_eq!(verifying_key.algorithm(), SignatureAlgorithm::Ed25519);

        verifying_key
            .verify_raw(SIGNED_DATA_RAW, b"Test message")
            .unwrap();
    }

    #[test]
    fn test_invalid_testvector() {
        let verifying_key = VerifyingKey::from_cose(&CoseKeyBytes::from(VERIFYING_KEY)).unwrap();
        assert_eq!(verifying_key.algorithm(), SignatureAlgorithm::Ed25519);

        // This should fail, as the signed object is not valid for the given verifying key.
        assert!(
            verifying_key
                .verify_raw(SIGNED_DATA_RAW, b"Invalid message")
                .is_err()
        );
    }
}
