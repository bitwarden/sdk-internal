use ciborium::value::Integer;
use coset::{CborSerializable, CoseSign1, iana::CoapContentFormat};
use serde::{Serialize, de::DeserializeOwned};

use super::{
    SigningNamespace, content_type, message::SerializedMessage, namespace, signing_key::SigningKey,
    verifying_key::VerifyingKey,
};
use crate::{
    CoseSign1Bytes, CryptoError,
    content_format::CoseSign1ContentFormat,
    cose::{CoseSerializable, SIGNING_NAMESPACE},
    error::{EncodingError, SignatureError},
};

/// A signed object is a message containing a payload and signature that attests the payload's
/// integrity and authenticity for a specific namespace and signature key. In order to gain access
/// to the payload, the caller must provide the correct namespace and verifying key, ensuring that
/// the caller cannot forget to validate the signature before using the payload.
#[derive(Clone, Debug)]
pub struct SignedObject(pub(crate) CoseSign1);

impl From<CoseSign1> for SignedObject {
    fn from(cose_sign1: CoseSign1) -> Self {
        SignedObject(cose_sign1)
    }
}

impl SignedObject {
    /// Parses the signature headers and returns the content type of the signed data. The content
    /// type indicates how the serialized message that was signed was encoded.
    pub fn content_type(&self) -> Result<CoapContentFormat, CryptoError> {
        content_type(&self.0.protected)
    }

    fn inner(&self) -> &CoseSign1 {
        &self.0
    }

    fn namespace(&self) -> Result<SigningNamespace, CryptoError> {
        namespace(&self.0.protected)
    }

    fn payload(&self) -> Result<Vec<u8>, CryptoError> {
        self.0
            .payload
            .as_ref()
            .ok_or(SignatureError::InvalidSignature.into())
            .map(|payload| payload.to_vec())
    }

    /// Verifies the signature of the signed object and returns the payload, if the signature is
    /// valid.
    pub fn verify_and_unwrap<Message: DeserializeOwned>(
        &self,
        verifying_key: &VerifyingKey,
        namespace: &SigningNamespace,
    ) -> Result<Message, CryptoError> {
        SerializedMessage::from_bytes(
            self.verify_and_unwrap_bytes(verifying_key, namespace)?,
            self.content_type()?,
        )
        .decode()
        .map_err(Into::into)
    }

    /// Verifies the signature of the signed object and returns the payload as raw bytes, if the
    /// signature is valid.
    fn verify_and_unwrap_bytes(
        &self,
        verifying_key: &VerifyingKey,
        namespace: &SigningNamespace,
    ) -> Result<Vec<u8>, CryptoError> {
        if self.inner().protected.header.alg.is_none() {
            return Err(SignatureError::InvalidSignature.into());
        }

        if self.namespace()? != *namespace {
            return Err(SignatureError::InvalidNamespace.into());
        }

        self.inner()
            .verify_signature(&[], |sig, data| verifying_key.verify_raw(sig, data))?;
        self.payload()
    }
}

impl SigningKey {
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
                    .content_format(serialized_message.content_type())
                    .value(
                        SIGNING_NAMESPACE,
                        ciborium::Value::Integer(Integer::from(namespace.as_i64())),
                    )
                    .build(),
            )
            .payload(serialized_message.as_bytes().to_vec())
            .create_signature(&[], |pt| self.sign_raw(pt))
            .build();
        Ok(SignedObject(cose_sign1))
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
    /// const EXAMPLE_NAMESPACE: SigningNamespace = SigningNamespace::SignedPublicKey;
    ///
    /// #[derive(Serialize, Deserialize, Debug, PartialEq)]
    /// struct TestMessage {
    ///   field1: String,
    /// }
    ///
    /// let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
    /// let message = TestMessage {
    ///   field1: "Test message".to_string(),
    /// };
    /// let namespace = EXAMPLE_NAMESPACE;
    /// let signed_object = signing_key.sign(&message, &namespace).unwrap();
    /// // The signed object can be verified using the verifying key:
    /// let verifying_key = signing_key.to_verifying_key();
    /// let payload: TestMessage = signed_object.verify_and_unwrap(&verifying_key, &namespace).unwrap();
    /// assert_eq!(payload, message);
    /// ```
    pub fn sign<Message: Serialize>(
        &self,
        message: &Message,
        namespace: &SigningNamespace,
    ) -> Result<SignedObject, CryptoError> {
        self.sign_bytes(&SerializedMessage::encode(message)?, namespace)
    }
}

impl CoseSerializable<CoseSign1ContentFormat> for SignedObject {
    fn from_cose(bytes: &CoseSign1Bytes) -> Result<Self, EncodingError> {
        Ok(SignedObject(
            CoseSign1::from_slice(bytes.as_ref())
                .map_err(|_| EncodingError::InvalidCoseEncoding)?,
        ))
    }

    fn to_cose(&self) -> CoseSign1Bytes {
        self.0
            .clone()
            .to_vec()
            .expect("SignedObject is always serializable")
            .into()
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use crate::{
        CoseKeyBytes, CoseSerializable, CoseSign1Bytes, CryptoError, SignatureAlgorithm,
        SignedObject, SigningKey, SigningNamespace, VerifyingKey,
    };

    const VERIFYING_KEY: &[u8] = &[
        166, 1, 1, 2, 80, 55, 131, 40, 191, 230, 137, 76, 182, 184, 139, 94, 152, 45, 63, 13, 71,
        3, 39, 4, 129, 2, 32, 6, 33, 88, 32, 93, 213, 35, 177, 81, 219, 226, 241, 147, 140, 238,
        32, 34, 183, 213, 107, 227, 92, 75, 84, 208, 47, 198, 80, 18, 188, 172, 145, 184, 154, 26,
        170,
    ];
    const SIGNED_OBJECT: &[u8] = &[
        132, 88, 30, 164, 1, 39, 3, 24, 60, 4, 80, 55, 131, 40, 191, 230, 137, 76, 182, 184, 139,
        94, 152, 45, 63, 13, 71, 58, 0, 1, 56, 127, 32, 160, 85, 161, 102, 102, 105, 101, 108, 100,
        49, 108, 84, 101, 115, 116, 32, 109, 101, 115, 115, 97, 103, 101, 88, 64, 206, 83, 177,
        184, 37, 103, 128, 39, 120, 174, 61, 4, 29, 184, 68, 46, 47, 203, 47, 246, 108, 160, 169,
        114, 7, 165, 119, 198, 3, 209, 52, 249, 89, 31, 156, 255, 212, 75, 224, 78, 183, 37, 174,
        63, 112, 70, 219, 246, 19, 213, 17, 121, 249, 244, 23, 182, 36, 193, 175, 55, 250, 65, 250,
        6,
    ];

    #[derive(Deserialize, Debug, PartialEq, Serialize)]
    struct TestMessage {
        field1: String,
    }

    #[test]
    fn test_roundtrip_cose() {
        let signed_object =
            SignedObject::from_cose(&<CoseSign1Bytes>::from(SIGNED_OBJECT)).unwrap();
        assert_eq!(
            signed_object.content_type().unwrap(),
            coset::iana::CoapContentFormat::Cbor
        );
        let cose_bytes = signed_object.to_cose();
        assert_eq!(cose_bytes, CoseSign1Bytes::from(SIGNED_OBJECT));
    }

    #[test]
    fn test_verify_and_unwrap_testvector() {
        let test_message = TestMessage {
            field1: "Test message".to_string(),
        };
        let signed_object =
            SignedObject::from_cose(&<CoseSign1Bytes>::from(SIGNED_OBJECT)).unwrap();
        let verifying_key = VerifyingKey::from_cose(&<CoseKeyBytes>::from(VERIFYING_KEY)).unwrap();
        let namespace = SigningNamespace::ExampleNamespace;
        let payload: TestMessage = signed_object
            .verify_and_unwrap(&verifying_key, &namespace)
            .unwrap();
        assert_eq!(payload, test_message);
    }

    #[test]
    fn test_sign_verify_and_unwrap_roundtrip() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
        let test_message = TestMessage {
            field1: "Test message".to_string(),
        };
        let namespace = SigningNamespace::ExampleNamespace;
        let signed_object = signing_key.sign(&test_message, &namespace).unwrap();
        let verifying_key = signing_key.to_verifying_key();
        let payload: TestMessage = signed_object
            .verify_and_unwrap(&verifying_key, &namespace)
            .unwrap();
        assert_eq!(payload, test_message);
    }

    #[test]
    fn test_fail_namespace_changed() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
        let test_message = TestMessage {
            field1: "Test message".to_string(),
        };
        let namespace = SigningNamespace::ExampleNamespace;
        let signed_object = signing_key.sign(&test_message, &namespace).unwrap();
        let verifying_key = signing_key.to_verifying_key();

        let different_namespace = SigningNamespace::ExampleNamespace2;
        let result: Result<TestMessage, CryptoError> =
            signed_object.verify_and_unwrap(&verifying_key, &different_namespace);
        assert!(result.is_err());
    }
}
