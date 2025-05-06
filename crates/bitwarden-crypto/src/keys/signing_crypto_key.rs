//! This file implements creation and verification of detached signatures

use ciborium::{value::Integer, Value};
use coset::{
    iana::{self, Algorithm, EllipticCurve, EnumI64, KeyOperation, KeyType, OkpKeyParameter},
    CborSerializable, CoseKey, CoseSign1, Label, RegisteredLabel, RegisteredLabelWithPrivate,
};
use ed25519_dalek::Signer;
use rand::rngs::OsRng;

use super::key_id::KeyId;
use crate::{cose::SIGNING_NAMESPACE, error::Result, signing::SigningNamespace, CryptoError};

#[allow(unused)]
enum SigningCryptoKeyEnum {
    Ed25519(ed25519_dalek::SigningKey),
}

#[allow(unused)]
enum VerifyingKeyEnum {
    Ed25519(ed25519_dalek::VerifyingKey),
}

#[allow(unused)]
struct SigningKey {
    id: KeyId,
    inner: SigningCryptoKeyEnum,
}

#[allow(unused)]
struct VerifyingKey {
    id: KeyId,
    inner: VerifyingKeyEnum,
}

#[allow(unused)]
impl SigningKey {
    fn make_ed25519() -> Result<Self> {
        Ok(SigningKey {
            id: KeyId::make(),
            inner: SigningCryptoKeyEnum::Ed25519(ed25519_dalek::SigningKey::generate(&mut OsRng)),
        })
    }

    fn cose_algorithm(&self) -> Algorithm {
        match &self.inner {
            SigningCryptoKeyEnum::Ed25519(_) => Algorithm::EdDSA,
        }
    }

    fn to_cose(&self) -> Result<Vec<u8>> {
        match &self.inner {
            SigningCryptoKeyEnum::Ed25519(key) => {
                coset::CoseKeyBuilder::new_okp_key()
                    .key_id((&self.id).into())
                    .algorithm(Algorithm::EdDSA)
                    // Note: X does not refer to the X coordinate of the public key curve point, but
                    // to the verifying key, as represented by the curve spec. In the
                    // case of Ed25519, this is the compressed Y coordinate. This was ill-defined in
                    // earlier drafts of the standard. https://www.rfc-editor.org/rfc/rfc9053.html#name-octet-key-pair
                    //
                    // Note: By the standard, the public key is optional (but RECOMMENDED) here, and
                    // can be derived on the fly.
                    .param(
                        OkpKeyParameter::X.to_i64(),
                        Value::Bytes(key.verifying_key().to_bytes().into()),
                    )
                    .param(
                        OkpKeyParameter::D.to_i64(),
                        Value::Bytes(key.to_bytes().into()),
                    )
                    .param(
                        OkpKeyParameter::Crv.to_i64(),
                        Value::Integer(Integer::from(EllipticCurve::Ed25519.to_i64())),
                    )
                    .add_key_op(KeyOperation::Sign)
                    .add_key_op(KeyOperation::Verify)
                    .build()
                    .to_vec()
                    .map_err(|_| CryptoError::InvalidKey)
            }
        }
    }

    fn from_cose(bytes: &[u8]) -> Result<Self> {
        let cose_key = CoseKey::from_slice(bytes).map_err(|_| CryptoError::InvalidKey)?;
        let (key_id, Some(algorithm), key_type) = (cose_key.key_id, cose_key.alg, cose_key.kty)
        else {
            return Err(CryptoError::InvalidKey);
        };
        let key_id: [u8; 16] = key_id
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        let key_id: KeyId = key_id.into();

        match (key_type, algorithm) {
            (kty, alg)
                if kty == RegisteredLabel::Assigned(KeyType::OKP)
                    && alg == RegisteredLabelWithPrivate::Assigned(Algorithm::EdDSA) =>
            {
                // https://www.rfc-editor.org/rfc/rfc9053.html#name-octet-key-pair
                let (mut crv, mut x, mut d) = (None, None, None);
                for (key, value) in &cose_key.params {
                    if let Label::Int(i) = key {
                        let key = OkpKeyParameter::from_i64(*i).ok_or(CryptoError::InvalidKey)?;
                        match key {
                            OkpKeyParameter::Crv => {
                                crv.replace(value);
                            }
                            OkpKeyParameter::X => {
                                x.replace(value);
                            }
                            OkpKeyParameter::D => {
                                d.replace(value);
                            }
                            _ => (),
                        }
                    }
                }

                let (Some(_x), Some(d), Some(crv)) = (x, d, crv) else {
                    return Err(CryptoError::InvalidKey);
                };
                let crv: i128 = crv.as_integer().ok_or(CryptoError::InvalidKey)?.into();
                if crv == EllipticCurve::Ed25519.to_i64().into() {
                    let secret_key_bytes: &[u8; 32] = d
                        .as_bytes()
                        .ok_or(CryptoError::InvalidKey)?
                        .as_slice()
                        .try_into()
                        .map_err(|_| CryptoError::InvalidKey)?;
                    let key = ed25519_dalek::SigningKey::from_bytes(secret_key_bytes);
                    Ok(SigningKey {
                        id: key_id,
                        inner: SigningCryptoKeyEnum::Ed25519(key),
                    })
                } else {
                    Err(CryptoError::InvalidKey)
                }
            }
            _ => Err(CryptoError::InvalidKey),
        }
    }

    pub(crate) fn sign(&self, namespace: &SigningNamespace, data: &[u8]) -> Signature {
        Signature::from(
            coset::CoseSign1Builder::new()
                .protected(
                    coset::HeaderBuilder::new()
                        .algorithm(self.cose_algorithm())
                        .key_id((&self.id).into())
                        .value(
                            SIGNING_NAMESPACE,
                            ciborium::Value::Integer(Integer::from(namespace.as_i64())),
                        )
                        .build(),
                )
                .create_detached_signature(data, &[], |pt| self.sign_raw(pt))
                .build(),
        )
    }

    /// Signs the given byte array with the signing key.
    /// This should never be used directly, but only through the `sign` method, to enforce
    /// strong domain separation of the signatures.
    fn sign_raw(&self, data: &[u8]) -> Vec<u8> {
        match &self.inner {
            SigningCryptoKeyEnum::Ed25519(key) => key.sign(data).to_bytes().to_vec(),
        }
    }

    fn to_verifying_key(&self) -> VerifyingKey {
        match &self.inner {
            SigningCryptoKeyEnum::Ed25519(key) => VerifyingKey {
                id: self.id.clone(),
                inner: VerifyingKeyEnum::Ed25519(key.verifying_key()),
            },
        }
    }
}

#[allow(unused)]
impl VerifyingKey {
    fn to_cose(&self) -> Result<Vec<u8>> {
        match &self.inner {
            VerifyingKeyEnum::Ed25519(key) => coset::CoseKeyBuilder::new_okp_key()
                .key_id((&self.id).into())
                .algorithm(Algorithm::EdDSA)
                .param(
                    OkpKeyParameter::Crv.to_i64(),
                    Value::Integer(Integer::from(EllipticCurve::Ed25519.to_i64())),
                )
                .param(
                    OkpKeyParameter::X.to_i64(),
                    Value::Bytes(key.to_bytes().to_vec()),
                )
                .add_key_op(KeyOperation::Verify)
                .build()
                .to_vec()
                .map_err(|_| CryptoError::InvalidKey),
        }
    }

    fn from_cose(bytes: &[u8]) -> Result<Self> {
        let cose_key = coset::CoseKey::from_slice(bytes).map_err(|_| CryptoError::InvalidKey)?;

        let (key_id, Some(algorithm), key_type) = (cose_key.key_id, cose_key.alg, cose_key.kty)
        else {
            return Err(CryptoError::InvalidKey);
        };
        let key_id: [u8; 16] = key_id
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        let key_id: KeyId = key_id.into();

        match (key_type, algorithm) {
            (kty, alg)
                if kty == RegisteredLabel::Assigned(KeyType::OKP)
                    && alg == RegisteredLabelWithPrivate::Assigned(Algorithm::EdDSA) =>
            {
                let (mut crv, mut x) = (None, None);
                for (key, value) in &cose_key.params {
                    if let coset::Label::Int(i) = key {
                        let key = OkpKeyParameter::from_i64(*i).ok_or(CryptoError::InvalidKey)?;
                        match key {
                            OkpKeyParameter::Crv => {
                                crv.replace(value);
                            }
                            OkpKeyParameter::X => {
                                x.replace(value);
                            }
                            _ => (),
                        }
                    }
                }
                let (Some(x), Some(crv)) = (x, crv) else {
                    return Err(CryptoError::InvalidKey);
                };

                let crv: i128 = crv.as_integer().ok_or(CryptoError::InvalidKey)?.into();
                if crv == iana::EllipticCurve::Ed25519.to_i64().into() {
                    let verifying_key_bytes: &[u8; 32] = x
                        .as_bytes()
                        .ok_or(CryptoError::InvalidKey)?
                        .as_slice()
                        .try_into()
                        .map_err(|_| CryptoError::InvalidKey)?;
                    let verifying_key =
                        ed25519_dalek::VerifyingKey::from_bytes(verifying_key_bytes)
                            .map_err(|_| CryptoError::InvalidKey)?;
                    Ok(VerifyingKey {
                        id: key_id,
                        inner: VerifyingKeyEnum::Ed25519(verifying_key),
                    })
                } else {
                    Err(CryptoError::InvalidKey)
                }
            }
            _ => Err(CryptoError::InvalidKey),
        }
    }

    /// Verifies the signature of the given data, for the given namespace.
    /// This should never be used directly, but only through the `verify` method, to enforce
    /// strong domain separation of the signatures.
    pub(crate) fn verify(
        &self,
        namespace: &SigningNamespace,
        signature: &Signature,
        data: &[u8],
    ) -> bool {
        let Some(_alg) = &signature.inner().protected.header.alg else {
            return false;
        };

        let Ok(signature_namespace) = signature.namespace() else {
            return false;
        };
        if signature_namespace != *namespace {
            return false;
        }

        signature
            .inner()
            .verify_detached_signature(data, &[], |sig, data| self.verify_raw(sig, data))
            .is_ok()
    }

    /// Verifies the signature of the given data, for the given namespace.
    /// This should never be used directly, but only through the `verify` method, to enforce
    /// strong domain separation of the signatures.
    fn verify_raw(&self, signature: &[u8], data: &[u8]) -> Result<()> {
        match &self.inner {
            VerifyingKeyEnum::Ed25519(key) => {
                let sig = ed25519_dalek::Signature::from_bytes(
                    signature
                        .try_into()
                        .map_err(|_| crate::error::CryptoError::InvalidSignature)?,
                );
                key.verify_strict(data, &sig)
                    .map_err(|_| crate::error::CryptoError::InvalidSignature)
            }
        }
    }
}

/// A signature cryptographically attests to a (namespace, data) pair. The namespace is included in
/// the signature object, the data is not. One data object can be signed multiple times, with
/// different namespaces / by different signers, depending on the application needs.
#[allow(unused)]
struct Signature(CoseSign1);

impl From<CoseSign1> for Signature {
    fn from(cose_sign1: CoseSign1) -> Self {
        Signature(cose_sign1)
    }
}

#[allow(unused)]
impl Signature {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let cose_sign1 = CoseSign1::from_slice(bytes).map_err(|_| CryptoError::InvalidSignature)?;
        Ok(Signature(cose_sign1))
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        self.0
            .clone()
            .to_vec()
            .map_err(|_| CryptoError::InvalidSignature)
    }

    fn inner(&self) -> &CoseSign1 {
        &self.0
    }

    fn namespace(&self) -> Result<SigningNamespace> {
        let mut namespace = None;
        for (key, value) in &self.0.protected.header.rest {
            if let Label::Int(key) = key {
                if *key == SIGNING_NAMESPACE {
                    namespace.replace(value);
                }
            }
        }
        let Some(namespace) = namespace else {
            return Err(CryptoError::InvalidNamespace);
        };
        let Some(namespace) = namespace.as_integer() else {
            return Err(CryptoError::InvalidNamespace);
        };
        let namespace: i128 = namespace.into();
        SigningNamespace::try_from_i64(namespace as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_roundtrip() {
        let signing_key = SigningKey::make_ed25519().unwrap();
        let verifying_key = signing_key.to_verifying_key();
        let data = b"Hello, world!";
        let namespace = SigningNamespace::EncryptionMetadata;

        let signature = signing_key.sign(&namespace, data);
        assert!(verifying_key.verify(&namespace, &signature, data));
    }

    #[test]
    fn test_changed_signature_fails() {
        let signing_key = SigningKey::make_ed25519().unwrap();
        let verifying_key = signing_key.to_verifying_key();
        let data = b"Hello, world!";
        let namespace = SigningNamespace::EncryptionMetadata;

        let signature = signing_key.sign(&namespace, data);
        assert!(!verifying_key.verify(&namespace, &signature, b"Goodbye, world!"));
    }

    #[test]
    fn test_changed_namespace_fails() {
        let signing_key = SigningKey::make_ed25519().unwrap();
        let verifying_key = signing_key.to_verifying_key();
        let data = b"Hello, world!";
        let namespace = SigningNamespace::EncryptionMetadata;
        let other_namespace = SigningNamespace::Test;

        let signature = signing_key.sign(&namespace, data);
        assert!(!verifying_key.verify(&other_namespace, &signature, data));
    }

    #[test]
    fn test_cose_roundtrip_encode_signing() {
        let signing_key = SigningKey::make_ed25519().unwrap();
        let cose = signing_key.to_cose().unwrap();
        let parsed_key = SigningKey::from_cose(&cose).unwrap();

        assert_eq!(
            signing_key.to_cose().unwrap(),
            parsed_key.to_cose().unwrap()
        );
    }

    #[test]
    fn test_cose_roundtrip_encode_verifying() {
        let signing_key = SigningKey::make_ed25519().unwrap();
        let cose = signing_key.to_verifying_key().to_cose().unwrap();
        let parsed_key = VerifyingKey::from_cose(&cose).unwrap();

        assert_eq!(
            signing_key.to_verifying_key().to_cose().unwrap(),
            parsed_key.to_cose().unwrap()
        );
    }
}
