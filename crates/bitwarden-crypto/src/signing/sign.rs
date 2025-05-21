//! Signing is used to assert integrity of a message to others or to oneself.
//!
//! Signing and signature verification operations are divided into three layers here:
//! - (public) High-level: Give a struct, namespace, and get a signed object or signature +
//!   serialized message. Purpose: Serialization should not be decided by the consumer of this
//!   interface, but rather by the signing implementation. Each consumer shouldn't have to make the
//!   decision on how to serialize. Further, the serialization format is written to the signature
//!   object, and verified.
//! - Mid-level: Give a byte array, content format, namespace, and get a signed object or signature.
//!   Purpose: All signatures should be domain-separated, so that any proofs only need to consider
//!   the allowed messages under the current namespace, and cross-protocol attacks are not possible.
//! - Low-level: Give a byte array, and get a signature. Purpose: This just implements the signing
//!   of byte arrays. Digital signature schemes generally just care about a set of input bytes to
//!   sign; and this operation implements that per-supported digital signature scheme. To add
//!   support for a new scheme, only this operation needs to be implemented for the new signing key
//!   type.
//!
//! Further, there are two kinds of signing operations supported here:
//! - Sign: Create a signed object that contains the payload. Purpose: If only one signature is
//!   needed for an object then it is simpler to keep the signature and payload together in one
//!   blob, so they cannot be separated.
//! - Sign detached: Create a signature that does not contain the payload; but the serialized
//!   payload is returned. Purpose: If multiple signatures are needed for one object, then sign
//!   detached can be used.

use ciborium::value::Integer;
use coset::iana::CoapContentFormat;
use ed25519_dalek::Signer;
use serde::{de::DeserializeOwned, Serialize};

use super::SigningNamespace;
use crate::{
    cose::SIGNING_NAMESPACE, error::SignatureError, CryptoError, RawSigningKey, RawVerifyingKey,
    Signature, SignedObject, SigningKey, VerifyingKey,
};

impl SigningKey {
    /// Signs the given payload with the signing key, under a given [`SigningNamespace`].
    /// This returns a [`Signature`] object, that does not contain the payload.
    /// The payload must be stored separately, and needs to be provided when verifying the
    /// signature.
    ///
    /// This should be used when multiple signers are required, or when signatures need to be
    /// replaceable without re-uploading the object, or if the signed object should be parseable
    /// by the server side, without the use of COSE on the server.
    /// ```
    /// use bitwarden_crypto::{SigningNamespace, SignatureAlgorithm, SigningKey};
    /// use serde::{Serialize, Deserialize};
    ///
    /// #[derive(Serialize, Deserialize, Debug, PartialEq)]
    /// struct TestMessage {
    ///  field1: String,
    /// }
    ///
    /// let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519).unwrap();
    /// let message = TestMessage {
    ///  field1: "Test message".to_string(),
    /// };
    /// let namespace = SigningNamespace::ExampleNamespace;
    /// let (signature, serialized_message) = signing_key.sign_detached(&message, &namespace).unwrap();
    /// // Verification
    /// let verifying_key = signing_key.to_verifying_key();
    /// assert!(verifying_key.verify_signature(&serialized_message.as_ref(), &namespace, &signature));
    /// ```
    #[allow(unused)]
    pub fn sign_detached<Message: Serialize>(
        &self,
        message: &Message,
        namespace: &SigningNamespace,
    ) -> Result<(Signature, SerializedMessage), CryptoError> {
        let message = encode_message(message)?;
        Ok((self.sign_detached_bytes(&message, namespace), message))
    }

    /// Given a serialized message, signature, this counter-signs the message. That is, if multiple
    /// parties want to sign the same message, one party creates the initial message, and the
    /// other parties then counter-sign it, and submit their signatures. This can be done as
    /// follows: ```
    /// let alice_key = SigningKey::make(SignatureAlgorithm::Ed25519).unwrap();
    /// let bob_key = SigningKey::make(SignatureAlgorithm::Ed25519).unwrap();
    ///
    /// let message = TestMessage {
    ///    field1: "Test message".to_string(),
    /// };
    /// let namespace = SigningNamespace::ExampleNamespace;
    /// let (signature, serialized_message) = alice_key.sign_detached(&message,
    /// &namespace).unwrap();\ // Alice shares (signature, serialized_message) with Bob.
    /// // Bob verifies the contents of serialized_message using application logic, then signs it:
    /// let (bob_signature, serialized_message) = bob_key.counter_sign(&serialized_message,
    /// &signature, &namespace).unwrap(); ```
    #[allow(unused)]
    pub fn counter_sign_detached(
        &self,
        serialized_message_bytes: Vec<u8>,
        initial_signature: &Signature,
        namespace: &SigningNamespace,
    ) -> Result<Signature, CryptoError> {
        // The namespace should be passed in to make sure the namespace the counter-signer is
        // expecting to sign for is the same as the one that the signer used
        if initial_signature.namespace()? != *namespace {
            return Err(SignatureError::InvalidNamespace.into());
        }

        Ok(self.sign_detached_bytes(
            &SerializedMessage {
                serialized_message_bytes,
                content_type: initial_signature.content_type()?,
            },
            namespace,
        ))
    }

    /// Signs the given payload with the signing key, under a given namespace.
    /// This is is the underlying implementation of the `sign_detached` method, and takes
    /// a raw byte array as input.
    fn sign_detached_bytes(
        &self,
        message: &SerializedMessage,
        namespace: &SigningNamespace,
    ) -> Signature {
        Signature::from(
            coset::CoseSign1Builder::new()
                .protected(
                    coset::HeaderBuilder::new()
                        .algorithm(self.cose_algorithm())
                        .key_id((&self.id).into())
                        .content_format(message.content_type)
                        .value(
                            SIGNING_NAMESPACE,
                            ciborium::Value::Integer(Integer::from(namespace.as_i64())),
                        )
                        .build(),
                )
                .create_detached_signature(&message.serialized_message_bytes, &[], |pt| {
                    self.sign_raw(pt)
                })
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
    /// ```
    /// use bitwarden_crypto::{SigningNamespace, SignatureAlgorithm, SigningKey};
    /// use serde::{Serialize, Deserialize};
    ///
    /// #[derive(Serialize, Deserialize, Debug, PartialEq)]
    /// struct TestMessage {
    ///   field1: String,
    /// }
    ///
    /// let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519).unwrap();
    /// let message = TestMessage {
    ///   field1: "Test message".to_string(),
    /// };
    /// let namespace = SigningNamespace::ExampleNamespace;
    /// let signed_object = signing_key.sign(&message, &namespace).unwrap();
    /// // The signed object can be verified using the verifying key:
    /// let verifying_key = signing_key.to_verifying_key();
    /// let payload: TestMessage = verifying_key.get_verified_payload(&signed_object, &namespace).unwrap();
    /// assert_eq!(payload, message);
    /// ```
    pub fn sign<Message: Serialize>(
        &self,
        message: &Message,
        namespace: &SigningNamespace,
    ) -> Result<SignedObject, CryptoError> {
        let message = encode_message(message)?;
        self.sign_bytes(&message, namespace)
    }

    /// Signs the given payload with the signing key, under a given namespace.
    /// This is is the underlying implementation of the `sign` method, and takes
    /// a raw byte array as input.
    fn sign_bytes(
        &self,
        serialized_message: &SerializedMessage,
        namespace: &SigningNamespace,
    ) -> Result<SignedObject, CryptoError> {
        let cose_sign1 = coset::CoseSign1Builder::new()
            .protected(
                coset::HeaderBuilder::new()
                    .algorithm(self.cose_algorithm())
                    .key_id((&self.id).into())
                    .content_format(serialized_message.content_type)
                    .value(
                        SIGNING_NAMESPACE,
                        ciborium::Value::Integer(Integer::from(namespace.as_i64())),
                    )
                    .build(),
            )
            .payload(serialized_message.serialized_message_bytes.clone())
            .create_signature(&[], |pt| self.sign_raw(pt))
            .build();
        Ok(SignedObject(cose_sign1))
    }

    /// Signs the given byte array with the signing key.
    /// This should never be used directly, but only through the `sign` method, to enforce
    /// strong domain separation of the signatures.
    fn sign_raw(&self, data: &[u8]) -> Vec<u8> {
        match &self.inner {
            RawSigningKey::Ed25519(key) => key.sign(data).to_bytes().to_vec(),
        }
    }
}

/// A message (struct), serialized to a byte array, along with the content format of the bytes.
pub struct SerializedMessage {
    serialized_message_bytes: Vec<u8>,
    content_type: CoapContentFormat,
}

impl AsRef<[u8]> for SerializedMessage {
    fn as_ref(&self) -> &[u8] {
        &self.serialized_message_bytes
    }
}

impl SerializedMessage {
    pub fn from_bytes(bytes: Vec<u8>, content_type: CoapContentFormat) -> Self {
        SerializedMessage {
            serialized_message_bytes: bytes,
            content_type,
        }
    }
}

impl VerifyingKey {
    /// Verifies the signature of the given serialized message bytes, created by
    /// [`SigningKey::sign_detached`], for the given namespace. The namespace must match the one
    /// used to create the signature.
    #[allow(unused)]
    pub fn verify_signature(
        &self,
        serialized_message_bytes: &[u8],
        namespace: &SigningNamespace,
        signature: &Signature,
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
            .verify_detached_signature(serialized_message_bytes, &[], |sig, data| {
                self.verify_raw(sig, data)
            })
            .is_ok()
    }

    /// Verifies the signature of a signed object, created by [`SigningKey::sign`], for the given
    /// namespace and returns the deserialized payload, if the signature is valid.
    pub fn get_verified_payload<Message: DeserializeOwned>(
        &self,
        signed_object: &SignedObject,
        namespace: &SigningNamespace,
    ) -> Result<Message, CryptoError> {
        let payload_bytes = self.get_verified_payload_bytes(signed_object, namespace)?;
        decode_message(&SerializedMessage {
            serialized_message_bytes: payload_bytes,
            content_type: signed_object.content_type()?,
        })
    }

    /// Verifies the signature of a signed object, created by [`SigningKey::sign`], for the given
    /// namespace and returns the raw payload bytes, if the signature is valid.
    fn get_verified_payload_bytes(
        &self,
        signed_object: &SignedObject,
        namespace: &SigningNamespace,
    ) -> Result<Vec<u8>, CryptoError> {
        let Some(_alg) = &signed_object.inner().protected.header.alg else {
            return Err(SignatureError::InvalidSignature.into());
        };

        let signature_namespace = signed_object.namespace()?;
        if signature_namespace != *namespace {
            return Err(SignatureError::InvalidNamespace.into());
        }

        signed_object
            .inner()
            .verify_signature(&[], |sig, data| self.verify_raw(sig, data))?;
        signed_object.payload()
    }

    /// Verifies the signature of the given data, for the given namespace.
    /// This should never be used directly, but only through the `verify` method, to enforce
    /// strong domain separation of the signatures.
    fn verify_raw(&self, signature: &[u8], data: &[u8]) -> Result<(), CryptoError> {
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

fn encode_message<Message: Serialize>(message: &Message) -> Result<SerializedMessage, CryptoError> {
    let mut buffer = Vec::new();
    ciborium::ser::into_writer(message, &mut buffer).map_err(|_| CryptoError::CoseEncodingError)?;
    Ok(SerializedMessage {
        serialized_message_bytes: buffer,
        content_type: CoapContentFormat::Cbor,
    })
}

fn decode_message<Message: DeserializeOwned>(
    message: &SerializedMessage,
) -> Result<Message, CryptoError> {
    if message.content_type != CoapContentFormat::Cbor {
        return Err(CryptoError::CoseEncodingError);
    }

    let decoded = ciborium::de::from_reader(message.serialized_message_bytes.as_slice())
        .map_err(|_| CryptoError::CoseEncodingError)?;
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;
    use crate::SignatureAlgorithm;

    /// The function used to create the test vectors below, and can be used to re-generate them.
    /// Once rolled out to user accounts, this function can be removed, because at that point we
    /// cannot introduce format-breaking changes anymore.
    #[test]
    fn make_test_vectors() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519).unwrap();
        let verifying_key = signing_key.to_verifying_key();
        let test_message = TestMessage {
            field1: "Test message".to_string(),
        };
        let namespace = SigningNamespace::ExampleNamespace;

        let (signature, serialized_message) = signing_key
            .sign_detached(&test_message, &namespace)
            .unwrap();
        let signed_object = signing_key.sign(&test_message, &namespace).unwrap();

        println!(
            "const SIGNING_KEY: &[u8] = &{:?};",
            signing_key.to_cose().unwrap()
        );
        println!(
            "const VERIFYING_KEY: &[u8] = &{:?};",
            verifying_key.to_cose().unwrap()
        );
        println!(
            "const SIGNATURE: &[u8] = &{:?};",
            signature.to_cose().unwrap()
        );
        println!(
            "const SERIALIZED_MESSAGE: &[u8] = &{:?};",
            serialized_message.serialized_message_bytes
        );
        println!(
            "const SIGNED_OBJECT: &[u8] = &{:?};",
            signed_object.to_cose().unwrap()
        );
    }

    const SIGNING_KEY: &[u8] = &[
        166, 1, 1, 2, 80, 91, 154, 106, 83, 253, 98, 76, 188, 129, 226, 105, 158, 216, 103, 155,
        16, 3, 39, 4, 130, 1, 2, 35, 88, 32, 114, 65, 45, 133, 77, 188, 130, 57, 89, 250, 113, 125,
        108, 138, 255, 68, 3, 202, 189, 96, 31, 218, 197, 24, 35, 127, 52, 168, 232, 85, 95, 199,
        32, 6,
    ];
    const VERIFYING_KEY: &[u8] = &[
        166, 1, 1, 2, 80, 91, 154, 106, 83, 253, 98, 76, 188, 129, 226, 105, 158, 216, 103, 155,
        16, 3, 39, 4, 129, 2, 32, 6, 33, 88, 32, 91, 255, 95, 169, 53, 21, 222, 134, 102, 103, 105,
        224, 58, 210, 82, 121, 141, 60, 76, 68, 9, 26, 242, 215, 111, 150, 228, 154, 141, 143, 108,
        38,
    ];
    const SIGNATURE: &[u8] = &[
        132, 88, 30, 164, 1, 39, 3, 24, 60, 4, 80, 91, 154, 106, 83, 253, 98, 76, 188, 129, 226,
        105, 158, 216, 103, 155, 16, 58, 0, 1, 56, 127, 32, 160, 246, 88, 64, 110, 91, 1, 209, 74,
        57, 108, 168, 211, 218, 58, 247, 112, 21, 205, 127, 120, 156, 192, 98, 81, 243, 61, 167,
        248, 236, 19, 115, 168, 62, 57, 170, 232, 138, 219, 159, 68, 193, 144, 100, 168, 10, 173,
        145, 72, 179, 236, 78, 94, 9, 135, 117, 153, 135, 126, 30, 70, 111, 109, 235, 85, 247, 99,
        14,
    ];
    const SERIALIZED_MESSAGE: &[u8] = &[
        161, 102, 102, 105, 101, 108, 100, 49, 108, 84, 101, 115, 116, 32, 109, 101, 115, 115, 97,
        103, 101,
    ];
    const SIGNED_OBJECT: &[u8] = &[
        132, 88, 30, 164, 1, 39, 3, 24, 60, 4, 80, 91, 154, 106, 83, 253, 98, 76, 188, 129, 226,
        105, 158, 216, 103, 155, 16, 58, 0, 1, 56, 127, 32, 160, 85, 161, 102, 102, 105, 101, 108,
        100, 49, 108, 84, 101, 115, 116, 32, 109, 101, 115, 115, 97, 103, 101, 88, 64, 110, 91, 1,
        209, 74, 57, 108, 168, 211, 218, 58, 247, 112, 21, 205, 127, 120, 156, 192, 98, 81, 243,
        61, 167, 248, 236, 19, 115, 168, 62, 57, 170, 232, 138, 219, 159, 68, 193, 144, 100, 168,
        10, 173, 145, 72, 179, 236, 78, 94, 9, 135, 117, 153, 135, 126, 30, 70, 111, 109, 235, 85,
        247, 99, 14,
    ];

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestMessage {
        field1: String,
    }

    #[test]
    fn test_vectors() {
        let signing_key = SigningKey::from_cose(SIGNING_KEY).unwrap();
        let verifying_key = VerifyingKey::from_cose(VERIFYING_KEY).unwrap();
        let signature = Signature::from_cose(SIGNATURE).unwrap();
        let signed_object = SignedObject::from_cose(SIGNED_OBJECT).unwrap();

        assert_eq!(signing_key.to_cose().unwrap(), SIGNING_KEY);
        assert_eq!(verifying_key.to_cose().unwrap(), VERIFYING_KEY);
        assert_eq!(signed_object.to_cose().unwrap(), SIGNED_OBJECT);

        assert_eq!(
            signature.namespace().unwrap(),
            SigningNamespace::ExampleNamespace
        );
        assert_eq!(signature.content_type().unwrap(), CoapContentFormat::Cbor);
        assert_eq!(signature.to_cose().unwrap(), SIGNATURE);

        assert_eq!(signed_object.payload().unwrap(), SERIALIZED_MESSAGE);
        assert_eq!(
            signed_object.namespace().unwrap(),
            SigningNamespace::ExampleNamespace
        );
        assert_eq!(
            signed_object.content_type().unwrap(),
            CoapContentFormat::Cbor
        );
        assert_eq!(signed_object.to_cose().unwrap(), SIGNED_OBJECT);

        let verified_payload: TestMessage = verifying_key
            .get_verified_payload(&signed_object, &SigningNamespace::ExampleNamespace)
            .unwrap();
        assert_eq!(
            verified_payload,
            TestMessage {
                field1: "Test message".to_string()
            }
        );
        assert!(verifying_key.verify_signature(
            SERIALIZED_MESSAGE,
            &SigningNamespace::ExampleNamespace,
            &signature
        ));
    }

    #[test]
    fn test_sign_detached_roundtrip() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519).unwrap();
        let verifying_key = signing_key.to_verifying_key();
        let data = TestMessage {
            field1: "Test message".to_string(),
        };
        let namespace = SigningNamespace::ExampleNamespace;
        let (signature, serialized_message) = signing_key.sign_detached(&data, &namespace).unwrap();
        assert!(verifying_key.verify_signature(
            &serialized_message.serialized_message_bytes,
            &namespace,
            &signature
        ));
        let decoded_message: TestMessage = decode_message(&serialized_message).unwrap();
        assert_eq!(decoded_message, data);
    }

    #[test]
    fn test_sign_roundtrip() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519).unwrap();
        let verifying_key = signing_key.to_verifying_key();
        let data = "Test message".to_string();
        let namespace = SigningNamespace::ExampleNamespace;
        let signed_object = signing_key.sign(&data, &namespace).unwrap();
        let payload: String = verifying_key
            .get_verified_payload(&signed_object, &namespace)
            .unwrap();
        assert_eq!(payload, data);
    }

    #[test]
    fn test_countersign_roundtrip() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519).unwrap();
        let verifying_key = signing_key.to_verifying_key();
        let data = "Test message".to_string();
        let namespace = SigningNamespace::ExampleNamespace;
        let (signature, serialized_message) = signing_key.sign_detached(&data, &namespace).unwrap();
        let countersignature = signing_key
            .counter_sign_detached(
                serialized_message.serialized_message_bytes.clone(),
                &signature,
                &namespace,
            )
            .unwrap();
        assert!(verifying_key.verify_signature(
            &serialized_message.serialized_message_bytes,
            &namespace,
            &countersignature
        ));
    }

    #[test]
    fn test_changed_payload_fails() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519).unwrap();
        let verifying_key = signing_key.to_verifying_key();
        let data = "Test message".to_string();
        let namespace = SigningNamespace::ExampleNamespace;

        let (signature, mut serialized_message) =
            signing_key.sign_detached(&data, &namespace).unwrap();
        let modified_message = serialized_message
            .serialized_message_bytes
            .get_mut(0)
            .unwrap();
        *modified_message = 0xFF;
        assert!(!verifying_key.verify_signature(
            &serialized_message.serialized_message_bytes,
            &namespace,
            &signature
        ));
    }

    #[test]
    fn test_changed_namespace_fails() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519).unwrap();
        let verifying_key = signing_key.to_verifying_key();
        let data = b"Test message";
        let namespace = SigningNamespace::ExampleNamespace;
        let other_namespace = SigningNamespace::PublicKeyOwnershipClaim;

        let (signature, serialized_message) = signing_key.sign_detached(&data, &namespace).unwrap();
        assert!(!verifying_key.verify_signature(
            &serialized_message.serialized_message_bytes,
            &other_namespace,
            &signature
        ));
        assert!(verifying_key.verify_signature(
            &serialized_message.serialized_message_bytes,
            &namespace,
            &signature
        ));
    }

    #[test]
    fn test_changed_namespace_fails_signed_object() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519).unwrap();
        let verifying_key = signing_key.to_verifying_key();
        let data = b"Test message";
        let namespace = SigningNamespace::ExampleNamespace;
        let other_namespace = SigningNamespace::PublicKeyOwnershipClaim;
        let signed_object = signing_key.sign(data, &namespace).unwrap();
        assert!(verifying_key
            .get_verified_payload::<Vec<u8>>(&signed_object, &other_namespace)
            .is_err());
        assert!(verifying_key
            .get_verified_payload::<Vec<u8>>(&signed_object, &namespace)
            .is_ok());
    }

    #[test]
    fn test_encode_decode_message() {
        let message = TestMessage {
            field1: "Hello".to_string(),
        };
        let encoded = encode_message(&message).unwrap();
        let decoded = decode_message(&encoded).unwrap();
        assert_eq!(message, decoded);
    }
}
