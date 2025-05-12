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

    /// Signs the given payload with the signing key, under a given namespace.
    /// This returns a [`Signature`] object, that does not contain the payload.
    /// The payload must be stored separately, and needs to be provided when verifying the
    /// signature.
    ///
    /// This should be used when multiple signers are required, or when signatures need to be
    /// replaceable without re-uploading the object, or if the signed object should be parseable
    /// by the server side, without the use of COSE on the server.
    pub(crate) fn sign_detached(&self, namespace: &SigningNamespace, data: &[u8]) -> Signature {
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

    /// Signs the given payload with the signing key, under a given namespace.
    /// This returns a [`SignedObject`] object, that contains the payload.
    /// The payload is included in the signature, and does not need to be provided when verifying
    /// the signature.
    ///
    /// This should be used when only one signer is required, so that only one object needs to be
    /// kept track of.
    pub(crate) fn sign(&self, namespace: &SigningNamespace, data: &[u8]) -> Result<SignedObject> {
        let cose_sign1 = coset::CoseSign1Builder::new()
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
            .payload(data.to_vec())
            .create_signature(&[], |pt| self.sign_raw(pt))
            .build();
        Ok(SignedObject(cose_sign1))
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
    pub(crate) fn verify_signature(
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

    /// Verifies the signature of a signed object, for the given namespace, and returns the payload.
    pub(crate) fn get_verified_payload(
        &self,
        namespace: &SigningNamespace,
        signature: &SignedObject,
    ) -> Result<Vec<u8>> {
        let Some(_alg) = &signature.inner().protected.header.alg else {
            return Err(CryptoError::InvalidSignature);
        };

        let signature_namespace = signature.namespace()?;
        if signature_namespace != *namespace {
            return Err(CryptoError::InvalidNamespace);
        }

        signature
            .inner()
            .verify_signature(&[], |sig, data| self.verify_raw(sig, data))?;
        signature.payload()
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
    fn from_cose(bytes: &[u8]) -> Result<Self> {
        let cose_sign1 = CoseSign1::from_slice(bytes).map_err(|_| CryptoError::InvalidSignature)?;
        Ok(Signature(cose_sign1))
    }

    fn to_cose(&self) -> Result<Vec<u8>> {
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

/// A signed object has a cryptographical attestation to a (namespace, data) pair. The namespace and
/// data are included in the signature object.
#[allow(unused)]
struct SignedObject(CoseSign1);

impl From<CoseSign1> for SignedObject {
    fn from(cose_sign1: CoseSign1) -> Self {
        SignedObject(cose_sign1)
    }
}

#[allow(unused)]
impl SignedObject {
    fn from_cose(bytes: &[u8]) -> Result<Self> {
        let cose_sign1 = CoseSign1::from_slice(bytes).map_err(|_| CryptoError::InvalidSignature)?;
        Ok(SignedObject(cose_sign1))
    }

    fn to_cose(&self) -> Result<Vec<u8>> {
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

    fn payload(&self) -> Result<Vec<u8>> {
        self.0
            .payload
            .as_ref()
            .ok_or(CryptoError::InvalidSignature)
            .map(|payload| payload.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNING_KEY: &[u8] = &[
        167, 1, 1, 2, 80, 222, 105, 244, 28, 22, 106, 70, 109, 171, 83, 154, 97, 23, 20, 115, 137,
        3, 39, 4, 130, 1, 2, 33, 88, 32, 92, 186, 140, 91, 228, 10, 169, 163, 132, 55, 210, 79, 96,
        186, 198, 251, 255, 79, 157, 58, 28, 182, 213, 118, 51, 15, 60, 110, 161, 114, 222, 168,
        35, 88, 32, 59, 136, 203, 0, 108, 23, 82, 84, 206, 163, 86, 62, 187, 196, 156, 156, 150,
        80, 101, 129, 247, 112, 117, 10, 34, 54, 254, 181, 239, 214, 195, 78, 32, 6,
    ];
    const VERIFYING_KEY: &[u8] = &[
        166, 1, 1, 2, 80, 222, 105, 244, 28, 22, 106, 70, 109, 171, 83, 154, 97, 23, 20, 115, 137,
        3, 39, 4, 129, 2, 32, 6, 33, 88, 32, 92, 186, 140, 91, 228, 10, 169, 163, 132, 55, 210, 79,
        96, 186, 198, 251, 255, 79, 157, 58, 28, 182, 213, 118, 51, 15, 60, 110, 161, 114, 222,
        168,
    ];
    /// Uses the ´SigningNamespace::EncryptionMetadata´ namespace, "Test message" as data
    const SIGNATURE: &[u8] = &[
        132, 88, 27, 163, 1, 39, 4, 80, 222, 105, 244, 28, 22, 106, 70, 109, 171, 83, 154, 97, 23,
        20, 115, 137, 58, 0, 1, 56, 127, 1, 160, 246, 88, 64, 143, 218, 162, 76, 208, 117, 94, 215,
        224, 98, 89, 193, 194, 226, 144, 214, 91, 130, 129, 130, 77, 36, 79, 196, 45, 105, 120,
        151, 136, 57, 230, 27, 37, 142, 55, 191, 23, 200, 237, 215, 252, 42, 182, 140, 201, 173,
        199, 214, 97, 105, 107, 101, 140, 182, 105, 9, 206, 106, 210, 29, 203, 174, 178, 12,
    ];

    #[test]
    fn test_using_test_vectors() {
        let signing_key = SigningKey::from_cose(SIGNING_KEY).unwrap();
        let verifying_key = VerifyingKey::from_cose(VERIFYING_KEY).unwrap();
        let signature = Signature::from_cose(SIGNATURE).unwrap();

        let data = b"Test message";
        let namespace = SigningNamespace::EncryptionMetadata;

        assert_eq!(signing_key.to_cose().unwrap(), SIGNING_KEY);
        assert_eq!(verifying_key.to_cose().unwrap(), VERIFYING_KEY);
        assert_eq!(signature.to_cose().unwrap(), SIGNATURE);

        assert!(verifying_key.verify_signature(&namespace, &signature, data));
    }

    #[test]
    fn test_sign_detached_roundtrip() {
        let signing_key = SigningKey::make_ed25519().unwrap();
        let verifying_key = signing_key.to_verifying_key();
        let data = b"Test message";
        let namespace = SigningNamespace::EncryptionMetadata;

        let signature = signing_key.sign_detached(&namespace, data);
        assert!(verifying_key.verify_signature(&namespace, &signature, data));
    }

    #[test]
    fn test_sign_roundtrip() {
        let signing_key = SigningKey::make_ed25519().unwrap();
        let verifying_key = signing_key.to_verifying_key();
        let data = b"Test message";
        let namespace = SigningNamespace::EncryptionMetadata;
        let signed_object = signing_key.sign(&namespace, data).unwrap();
        let payload = verifying_key
            .get_verified_payload(&namespace, &signed_object)
            .unwrap();
        assert_eq!(payload, data);
    }

    #[test]
    fn test_changed_payload_fails() {
        let signing_key = SigningKey::make_ed25519().unwrap();
        let verifying_key = signing_key.to_verifying_key();
        let data = b"Test message";
        let namespace = SigningNamespace::EncryptionMetadata;

        let signature = signing_key.sign_detached(&namespace, data);
        assert!(!verifying_key.verify_signature(&namespace, &signature, b"Test message 2"));
    }

    #[test]
    fn test_changed_namespace_fails() {
        let signing_key = SigningKey::make_ed25519().unwrap();
        let verifying_key = signing_key.to_verifying_key();
        let data = b"Test message";
        let namespace = SigningNamespace::EncryptionMetadata;
        let other_namespace = SigningNamespace::Test;

        let signature = signing_key.sign_detached(&namespace, data);
        assert!(!verifying_key.verify_signature(&other_namespace, &signature, data));
    }

    #[test]
    fn test_changed_namespace_fails_signed_object() {
        let signing_key = SigningKey::make_ed25519().unwrap();
        let verifying_key = signing_key.to_verifying_key();
        let data = b"Test message";
        let namespace = SigningNamespace::EncryptionMetadata;
        let other_namespace = SigningNamespace::Test;
        let signed_object = signing_key.sign(&namespace, data).unwrap();
        assert!(verifying_key
            .get_verified_payload(&other_namespace, &signed_object)
            .is_err());
    }

    #[test]
    fn test_cose_roundtrip_signature() {
        let signing_key = SigningKey::make_ed25519().unwrap();
        let cose =
            signing_key.sign_detached(&SigningNamespace::EncryptionMetadata, b"Test message");
        let cose = cose.to_cose().unwrap();
        let parsed_cose = Signature::from_cose(&cose).unwrap();
        assert_eq!(cose, parsed_cose.to_cose().unwrap());
    }

    #[test]
    fn test_cose_roundtrip_signed_object() {
        let signing_key = SigningKey::make_ed25519().unwrap();
        let cose = signing_key
            .sign(&SigningNamespace::EncryptionMetadata, b"Test message")
            .unwrap();
        let cose = cose.to_cose().unwrap();
        let parsed_cose = SignedObject::from_cose(&cose).unwrap();
        assert_eq!(cose, parsed_cose.to_cose().unwrap());
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
