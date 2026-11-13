use std::str::FromStr;

use bitwarden_crypto::{
    CoseKeyBytes, CoseSerializable, CoseSign1Bytes, CryptoError, EncString, EncodingError, KeyId,
    PublicKey, SignedObject, UnsignedSharedKey, VerifyingKey,
    compat::LegacyCompatSymmetricKeyEnvelope,
    safe::{DataEnvelope, PasswordProtectedKeyEnvelope, SymmetricKeyEnvelope},
};
use bitwarden_encoding::B64;

use crate::{
    ServerError,
    inspection::{
        CryptoObjectKeyIds, EncStringInfo, PublicKeyInfo, UnsignedSharedKeyInfo, VerifyingKeyInfo,
    },
};

/// Parses SDK crypto objects and reads the key ids they name, without decrypting or verifying.
#[derive(uniffi::Object)]
pub struct CryptoParsingClient;

#[uniffi::export]
impl CryptoParsingClient {
    /// Inspects an EncString: its algorithm and encrypting key.
    pub fn inspect_enc_string(&self, enc_string: String) -> Result<EncStringInfo, ServerError> {
        EncStringInfo::try_from(&EncString::parse_strict(&enc_string)?)
    }

    /// Inspects an UnsignedSharedKey: its algorithm.
    pub fn inspect_unsigned_shared_key(
        &self,
        shared_key: String,
    ) -> Result<UnsignedSharedKeyInfo, ServerError> {
        Ok(UnsignedSharedKeyInfo::from(&UnsignedSharedKey::from_str(
            &shared_key,
        )?))
    }

    /// Inspects a SymmetricKeyEnvelope: the sealed key and the sealing key.
    pub fn inspect_symmetric_key_envelope(
        &self,
        envelope: String,
    ) -> Result<CryptoObjectKeyIds, ServerError> {
        let envelope = SymmetricKeyEnvelope::from_str(&envelope)?;

        Ok(CryptoObjectKeyIds {
            contained_key_id: envelope.contained_key_id()?.map(|id| id.to_string()),
            encrypted_by_key_id: Some(envelope.encrypted_by_key_id()?.to_string()),
            ..Default::default()
        })
    }

    /// Inspects a LegacyCompatSymmetricKeyEnvelope: the sealed key and the sealing key.
    pub fn inspect_legacy_compat_symmetric_key_envelope(
        &self,
        envelope: String,
    ) -> Result<CryptoObjectKeyIds, ServerError> {
        let envelope = LegacyCompatSymmetricKeyEnvelope::from_str(&envelope)?;

        // The SDK parses the EncString form laxly; reject what it could not read.
        if let LegacyCompatSymmetricKeyEnvelope::EncString(EncString::Unparseable { .. }) =
            &envelope
        {
            return Err(ServerError::InvalidData);
        }

        Ok(CryptoObjectKeyIds {
            contained_key_id: envelope.contained_key_id()?.map(|id| id.to_string()),
            encrypted_by_key_id: envelope.encrypted_by_key_id()?.map(|id| id.to_string()),
            ..Default::default()
        })
    }

    /// Inspects a PasswordProtectedKeyEnvelope: the sealed key.
    pub fn inspect_password_protected_key_envelope(
        &self,
        envelope: String,
    ) -> Result<CryptoObjectKeyIds, ServerError> {
        Ok(CryptoObjectKeyIds {
            contained_key_id: PasswordProtectedKeyEnvelope::from_str(&envelope)?
                .contained_key_id()?
                .map(|id| id.to_string()),
            ..Default::default()
        })
    }

    /// Inspects a DataEnvelope: the content-encryption key it is sealed with.
    pub fn inspect_data_envelope(
        &self,
        envelope: String,
    ) -> Result<CryptoObjectKeyIds, ServerError> {
        Ok(CryptoObjectKeyIds {
            encrypted_by_key_id: Some(
                DataEnvelope::from_str(&envelope)
                    .map_err(|_| ServerError::InvalidData)?
                    .encrypted_by_key_id()?
                    .to_string(),
            ),
            ..Default::default()
        })
    }

    /// Inspects a SignedObject: the signing key.
    pub fn inspect_signed_object(
        &self,
        signed_object: String,
    ) -> Result<CryptoObjectKeyIds, ServerError> {
        Ok(signed_by_ids(signed_by(&signed_object)?))
    }

    /// Inspects a VerifyingKey: its algorithm and key id.
    pub fn inspect_verifying_key(
        &self,
        verifying_key: String,
    ) -> Result<VerifyingKeyInfo, ServerError> {
        let bytes = B64::try_from(verifying_key.as_str()).map_err(|_| ServerError::InvalidData)?;

        Ok(VerifyingKeyInfo::from(&VerifyingKey::from_cose(
            &CoseKeyBytes::from(&bytes),
        )?))
    }

    /// Inspects a PublicKey: its algorithm and key id.
    pub fn inspect_public_key(&self, public_key: String) -> Result<PublicKeyInfo, ServerError> {
        PublicKeyInfo::try_from(
            &PublicKey::from_str(&public_key).map_err(|_| ServerError::InvalidData)?,
        )
    }
}

/// Parses a base64 COSE Sign1 SignedObject and returns its signing key id.
fn signed_by(signed_object: &str) -> Result<KeyId, CryptoError> {
    let bytes = B64::try_from(signed_object).map_err(|_| EncodingError::InvalidBase64Encoding)?;

    SignedObject::from_cose(&CoseSign1Bytes::from(&bytes))?.signed_by_id()
}

/// Key ids of a signed object.
fn signed_by_ids(signed_by: KeyId) -> CryptoObjectKeyIds {
    CryptoObjectKeyIds {
        signed_by_key_id: Some(signed_by.to_string()),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        EncStringAlgorithm, PublicKeyAlgorithm, ServerClient, UnsignedSharedKeyAlgorithm,
        VerifyingKeyAlgorithm,
    };

    /// Reaches the sub-client the way bindings do, through [ServerClient].
    fn client() -> CryptoParsingClient {
        ServerClient::new().crypto_parsing()
    }

    const GARBAGE: &str = "garbage";

    // EncStrings and a SymmetricKeyEnvelope, mirrored in the dotnet-extensions tests.
    // `COSE_ENCSTRING` is encrypted with the XAES-256-GCM key `FIXTURE_KEY_ID`; `ENVELOPE` seals it
    // with `ENVELOPE_WRAPPING_KEY_ID`.
    const FIXTURE_KEY_ID: &str = "786b476843503fe1f6deb3951ef8f037";
    const ENVELOPE_WRAPPING_KEY_ID: &str = "f145204af724a7dcf111dc72fbdf504c";
    const COSE_ENCSTRING: &str = "7.g1g/owE6AAEReQN4I2FwcGxpY2F0aW9uL3guYml0d2FyZGVuLnV0ZjgtcGFkZGVkBFB4a0doQ1A/4fbes5Ue+PA3oQVYGDyfZwmpm8qoMQ6T/GkNaSNiH0xURegyi1gwqCiYSKv1pO6JGK65CMOYx4dAUaqpKz5JlvFE/XdTX6VcOggf2PX0H9iCB/rDjvng";
    const LEGACY_ENCSTRING: &str = "2.lydV844NLeMlZyw+lBvavQ==|g/ybWBsaTkyTDJYL1kcrZQ==|2ZeoX1YiRQoaowBuGS7feAH9PZvz3VDy6QuPtMNu7R4=";
    const AES256_CBC_ENCSTRING: &str = "0.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==";
    const ENVELOPE: &str = "g1g+pgE6AAEReQMYZQRQ8UUgSvckp9zxEdxy+99QTDoAARVcUHhrR2hDUD/h9t6zlR748Dc6AAE4gQM6AAE4gAKhBVgYHYM4amZXcPx+ioIiaBQXy/itml3h/5kpWFR2SQ9uMP9TBs/iL2+tuzwOcGtphqCkEpSBBlifIzT9oow7+hYJ9N4hKxXYLEn0ldNDdfi7ryjXgAscY0OTDPOEIwUaqJZGKESUEDDhohHVoaGgZrY=";

    // RSA-OAEP-SHA1 (type 4).
    const UNSIGNED_SHARED_KEY: &str = "4.BIq2tr44ZiRJxwzufq+4DyJFgmsHltGVanQGipZvXMO90tPG9dXtZGNBESOSuOp4Qv9t2Von4tARVGl9e+0AHXGy8/qcxU2jj2eSrFyOlp/5QKdKhbPLQcsXA8fzNZVhGAraMUJxIN/BULOLUhOvdRVsrlMUTJ1FHTautMssPdDtpJt5a9Ilsjp3Y3lT6iXp8TxeCUxbExz67+AdxZNOmQ5Im5K0ZQRg2vsGeLOUumdFY+MKdmneNw12KwoY1eADeBDGsb7uL4gP2CdfssSnbRNZLT0sGDw8vZ/3DEI0Ouv9OqH0Er8peaL/jhu+yFj3jJjrO6FB8BgOiaRM6Tle0A==";

    // The legacy compat envelope, in both forms, and the password-protected envelope seal the
    // XAES-256-GCM key `SEALED_KEY_ID`; the legacy compat ones with `WRAPPING_KEY_ID`.
    const SEALED_KEY_ID: &str = "53566663343d8fc222a3900d58b65b77";
    const WRAPPING_KEY_ID: &str = "248997c0da9c52d6a32debaa586ff1bd";
    const LEGACY_COMPAT_ENVELOPE: &str = "g1g+pgE6AAEReQMYZQRQJImXwNqcUtajLeuqWG/xvToAARVcUFNWZmM0PY/CIqOQDVi2W3c6AAE4gQM6AAE4gAKhBVgYkE18T0RcUKhPxS4276OJEuqzsS6m83u0WFSq9yTDddg95kZXg5gb1Zt/rmtQG5EHtbyu489erM0nYGOPLyyJm6YZgyxb1qOKQaKva2K27/HnUY5AeH/LmP1AYk6Fj98MR7Ruy/L2mcvoEEB2pQY=";
    const LEGACY_COMPAT_ENC_STRING: &str = "7.g1gcowE6AAEReQMYZQRQJImXwNqcUtajLeuqWG/xvaEFWBgzyAQv7mqA9wN2nlIXBByH41fSMs+OfuNYVJWKV7gG5J1BSjIBIjVqaPnF0MfCuu04atkyQJ3oI9EPfJEEbMaNTQFp36IgCpDfbOzZwFgMNWhEI8VsTt9kKU+72BdOcn1tQl6Qp9qmCc/qxT7uCQ==";
    const PASSWORD_PROTECTED_ENVELOPE: &str = "hFgopQEDAxhlOgABFVxQU1ZmYzQ9j8Iio5ANWLZbdzoAATiBAToAATiAAaEFTJgzQ4sUhzkdY4gteFhU2ndtN+QQKfrj2nSef1SqUK/gQlyQu6qsaBsndHY3Ph1aYDqkKz+T57Lm6DJ4VzqUw5J2ortTAALAbUJxTgtk8G3NvIn9Y60M4KC+lO9nYgcvlaVEgYNHoQE6AAEVV6UBOgABFVc6AAEVWQM6AAEVWhoAAQAAOgABFVsEOgABFVhQCOtRrpiR4W5fdBEC0JXGcPY=";

    const DATA_ENVELOPE: &str = "g1hHpQEDA3gjYXBwbGljYXRpb24veC5iaXR3YXJkZW4uY2Jvci1wYWRkZWQEUCOWPR8YkDliAz/dcDPX9KU6AAE4gQI6AAE4gAGhBUyPajh379VogJdpvsZYULG1mL5ZH8uMD+KRnEFz6pdyt0oPaEAhFMTPYzGr0x2mQwE+/pu7C7n/v64yMGNQA83jTtVMxQbdg72nlKY1A6zyXJGTB3IWPepd+2kmG6D/";
    const DATA_ENVELOPE_KEY_ID: &str = "23963d1f18903962033fdd7033d7f4a5";

    // `SIGNED_OBJECT` is signed by the Ed25519 key `ED25519_VERIFYING_KEY`.
    const SIGNED_OBJECT: &str = "hFgepAEnAxg8BFAnJn/sIHXsmiBAUd0HqJQvOgABOH8CoEqhZ3ZlcnNpb24CWECP4SQzOTGoK/XrpzXLRsknftlHgHxnNg4C5NcWjUb2lc6jZFy78m8p5nLVTRm/ocDktAZbq7cjSYpwgm3lVxgP";
    const ED25519_VERIFYING_KEY: &str =
        "pgEBAlAnJn/sIHXsmiBAUd0HqJQvAycEgQIgBiFYIK4qOBEFD+9QEIUdPBUaKZimZocq1AfYoNdyVYr23V5Y";
    const ED25519_KEY_ID: &str = "27267fec2075ec9a204051dd07a8942f";
    const MLDSA44_VERIFYING_KEY: &str = "pQEHAlAILVpe94MCxV5y8+0huNHkAzgvBIECIFkFIKDbDLzn3vqKlw8eQluffZu+9c9I7ob5FDwM6i41uu82mQ2QUkZWtm08U3LfRHQcbS4im60eI24+Qwq1RG4Yq9VuPkjsPM43471DOW8ND+M8OBIJnPU+QwfVuO2ZwW9jBljn8F25R9dCR8/TpQBZL8XsfOPZycQuHjMuwvgIKDuTeqndjBBWr1FMQbHfuTpVQwqVIZpL3X+fdFErUfIyH2QfH8JNRGqJl7bSlVp7Tg+n58+TJxDyvyljp0jki1S73qyAUtzNQgPYdjGdhJeyljCVWhrKzMFk9kFffdF9iTMLO2umcWK+RrqOJ9Oy9pCTGcicMRzOZg/IF7UObXJ8ZmXIQt4UTCVXlMamMQy+0fqcWxAXqo0EgcN3CbG/s6DNiOzAnH/Un8uMv9CuZ5EAGxZbn7YbUWHmMcNy93etWGBFllmkKosNmbr0QJ2AQWDHtLNidXF5CJjtXp+hp4QZ/TVa99To+V6pvTvEv5m6C6a+ElEvROhn1yAR/WqU9RdZNB8/8rqlL35vMCeztyaku++zgDNPh9f843pL09+OfHkVX/hqKAf8MhKl2Qr8+b14jng9Bn9PX+Cn6zEdxZcTXzjc01jq9WwfUKMzgfiemaoJrDT4s3WpT6qjujmqEva5dUQGjZbRj21KcRUeeaa9C5aGrFjR+z4wEsZTn9R/kwlDd/mxqkoZ4Kpc+9/szeUQdB6VhP0qdohwet9HLmKLn/YjPEdyK0Ac2CKmkzxgoPPV6c3sNj1wcp3PVo7umcxn0BKGIW6OT762tRSwpZFzWpapYjS5oUt0gbK581PaJvcB9B4cZgpz6BN4dnNz5OVHfurqaAfKDw36y04mV/QNpCv01tEweoXF+Ha9hqor+KvSz/NP9vYZ94Fj8Whad3RehO4aHuYqqeRyF6dwezLQmvVOVRyQXNWzkQRrjtKkEji03XXIOx3U9WizQr9tR8lgc57kkngZN9VgpvF23vDC7Cj2XSThILH7hTTUDBc0FF9N9RvJJVBjGSNrWWmGF+bwsz6sTB2gTgujCaYXEBuEcStAMSTILOq5CdFEDDJIl98NcLmE/qgDifhwTq2wqDekakaAXuDuTW6P+oPZdNfFSJ6BOEG/Z6asE9SCcVzmSLWR2oE+Ol1BmVEaSTqqP+eMJ6G+YHkyPXipS8RtbDmjXcHnEpKrGy0Zqcnm7aGzgCCZTC+p0Hs5iE+l1/5P7ljVtmL4Ct/ZnVttG+XMln4igr0ED6ZHGKCJJA93kfblAIdhiez3RQGIONuXOlmmmUqGcwNmQPomIn7HKxSMCNuZXNOr7qM/ODiGzD+TtBKwiR4WwijhpfcRanCL6VPAwV+Oq2367VI5XJInJxiRHl4Mm0IIvNrnOLL2YkLG956yz9rYKBm+Rs84K8jCTMSnsDE45fc2DvLekobtOvNy1bZRhkdgxSUOgmwum9uZzv7eatFI3hu8hA5sk7fY8Wi2mQWMztPx2H4cRE/9jWIfIciG9WSMnFzhowBdWaTIP7SwJx1WfssfbAll22u2BFyZCNFIg4eG4UHPpa6i8QQzx9dSh81lRP27AKbbSPl3RMMzy79i0RN2BQmNJP3BZWMzUsmO1N/fkgpjk5SA2tfxhwDntZmZEfAeMMbu6XlYQVfDbuAxj59XEtN0V2Luk2wExCGMJ+P3+8a4VvlBRZDXO8HBYw7tFlHfN8pEfA3ad43MMGerqCw6W0BigynIWWpHi0WjFLZbmvz8wuM5x8o+++wFzYI=";
    const MLDSA44_KEY_ID: &str = "082d5a5ef78302c55e72f3ed21b8d1e4";

    // RSA-2048 SPKI.
    const PUBLIC_KEY: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxiXYn+w+Fln8DCG1wmsm2ARyousIze1Jt3Fl55iOdD5kcWc71hLgiwvEGYmHqec5Ztl16Z2CuHtUrZhExRvXegVPPyOJU2lbsxw8okF+JXX+0vK7x9rNR4q4EZOHEwbU77H+EnwpAkkSaVAsH38tJq3lztlosELDXY7QA8S+HHhLsaj9d12crCixaZVE9ckTEFxraMtJQ4ur5O0KBDToC4xouPwzQzZbbXFIjjhfBbsQjN7lf4mky3bg0VvMgB5QA8tCUq35ActZrQXQJYj7C3uNcGr7DnJjVsjlRZ9f3b7tJIUDHTSt7AqhkoVlbf0C/lUVtIY9Va8RBpWcAjMJEQIDAQAB";
    const PUBLIC_KEY_ID: &str = "dac064e9c0a6a07547a2dd16de0790f8";

    #[test]
    fn inspect_enc_string() {
        let client = client();

        for (input, algorithm, key_id) in [
            (
                COSE_ENCSTRING,
                EncStringAlgorithm::XAes256Gcm,
                Some(FIXTURE_KEY_ID),
            ),
            (LEGACY_ENCSTRING, EncStringAlgorithm::Aes256CbcHmac, None),
            (AES256_CBC_ENCSTRING, EncStringAlgorithm::Aes256Cbc, None),
        ] {
            let info = client.inspect_enc_string(input.into()).expect(input);

            assert_eq!(
                info,
                EncStringInfo {
                    algorithm,
                    encrypted_by_key_id: key_id.map(str::to_string),
                },
                "{input}"
            );
        }
    }

    #[test]
    fn inspect_enc_string_invalid() {
        let client = client();

        // An UnsignedSharedKey is not an EncString.
        for input in [GARBAGE, "2.AAAA|AAAA", "9.AAAA", UNSIGNED_SHARED_KEY] {
            let result = client.inspect_enc_string(input.into());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{input}");
        }
    }

    #[test]
    fn inspect_unsigned_shared_key() {
        let info = client()
            .inspect_unsigned_shared_key(UNSIGNED_SHARED_KEY.into())
            .expect("valid UnsignedSharedKey");

        assert_eq!(
            info,
            UnsignedSharedKeyInfo {
                algorithm: UnsignedSharedKeyAlgorithm::Rsa2048OaepSha1,
            }
        );
    }

    #[test]
    fn inspect_unsigned_shared_key_invalid() {
        let client = client();

        for input in [GARBAGE, COSE_ENCSTRING, LEGACY_ENCSTRING] {
            let result = client.inspect_unsigned_shared_key(input.into());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{input}");
        }
    }

    #[test]
    fn inspect_symmetric_key_envelope() {
        let ids = client()
            .inspect_symmetric_key_envelope(ENVELOPE.into())
            .expect("valid envelope");

        assert_eq!(
            ids,
            CryptoObjectKeyIds {
                contained_key_id: Some(FIXTURE_KEY_ID.to_string()),
                encrypted_by_key_id: Some(ENVELOPE_WRAPPING_KEY_ID.to_string()),
                signed_by_key_id: None,
            }
        );
    }

    #[test]
    fn inspect_symmetric_key_envelope_invalid() {
        let client = client();

        for input in [GARBAGE, COSE_ENCSTRING] {
            let result = client.inspect_symmetric_key_envelope(input.into());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{input}");
        }
    }

    #[test]
    fn inspect_legacy_compat_symmetric_key_envelope() {
        let client = client();

        for (input, contained) in [
            (LEGACY_COMPAT_ENVELOPE, Some(SEALED_KEY_ID)),
            (LEGACY_COMPAT_ENC_STRING, None),
        ] {
            let ids = client
                .inspect_legacy_compat_symmetric_key_envelope(input.into())
                .expect(input);

            assert_eq!(
                ids,
                CryptoObjectKeyIds {
                    contained_key_id: contained.map(str::to_string),
                    encrypted_by_key_id: Some(WRAPPING_KEY_ID.to_string()),
                    signed_by_key_id: None,
                },
                "{input}"
            );
        }
    }

    #[test]
    fn inspect_legacy_compat_symmetric_key_envelope_invalid() {
        let client = client();

        for input in [GARBAGE, "2.AAAA|AAAA"] {
            let result = client.inspect_legacy_compat_symmetric_key_envelope(input.into());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{input}");
        }
    }

    #[test]
    fn inspect_password_protected_key_envelope() {
        let ids = client()
            .inspect_password_protected_key_envelope(PASSWORD_PROTECTED_ENVELOPE.into())
            .expect("valid envelope");

        assert_eq!(
            ids,
            CryptoObjectKeyIds {
                contained_key_id: Some(SEALED_KEY_ID.to_string()),
                ..Default::default()
            }
        );
    }

    #[test]
    fn inspect_password_protected_key_envelope_invalid() {
        let client = client();

        for input in [GARBAGE, ENVELOPE] {
            let result = client.inspect_password_protected_key_envelope(input.into());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{input}");
        }
    }

    #[test]
    fn inspect_data_envelope() {
        let ids = client()
            .inspect_data_envelope(DATA_ENVELOPE.into())
            .expect("valid envelope");

        assert_eq!(
            ids,
            CryptoObjectKeyIds {
                encrypted_by_key_id: Some(DATA_ENVELOPE_KEY_ID.to_string()),
                ..Default::default()
            }
        );
    }

    #[test]
    fn inspect_data_envelope_invalid() {
        let client = client();

        // Not base64; base64 but not COSE.
        for input in [GARBAGE, "AAAA"] {
            let result = client.inspect_data_envelope(input.into());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{input}");
        }
    }

    #[test]
    fn inspect_signed_object() {
        let ids = client()
            .inspect_signed_object(SIGNED_OBJECT.into())
            .expect("valid SignedObject");

        assert_eq!(
            ids,
            CryptoObjectKeyIds {
                signed_by_key_id: Some(ED25519_KEY_ID.to_string()),
                ..Default::default()
            }
        );
    }

    #[test]
    fn inspect_signed_object_invalid() {
        let client = client();

        for input in [GARBAGE, "AAAA"] {
            let result = client.inspect_signed_object(input.into());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{input}");
        }
    }

    #[test]
    fn inspect_verifying_key() {
        let client = client();

        for (input, algorithm, key_id) in [
            (
                ED25519_VERIFYING_KEY,
                VerifyingKeyAlgorithm::Ed25519,
                ED25519_KEY_ID,
            ),
            (
                MLDSA44_VERIFYING_KEY,
                VerifyingKeyAlgorithm::MlDsa44,
                MLDSA44_KEY_ID,
            ),
        ] {
            let info = client.inspect_verifying_key(input.into()).expect(input);

            assert_eq!(
                info,
                VerifyingKeyInfo {
                    algorithm,
                    key_id: key_id.to_string(),
                }
            );
        }
    }

    #[test]
    fn inspect_verifying_key_invalid() {
        let client = client();

        for input in [GARBAGE, "AAAA"] {
            let result = client.inspect_verifying_key(input.into());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{input}");
        }
    }

    #[test]
    fn inspect_public_key() {
        let info = client()
            .inspect_public_key(PUBLIC_KEY.into())
            .expect("valid PublicKey");

        assert_eq!(
            info,
            PublicKeyInfo {
                algorithm: PublicKeyAlgorithm::RsaOaepSha1,
                key_id: PUBLIC_KEY_ID.to_string(),
            }
        );
    }

    #[test]
    fn inspect_public_key_invalid() {
        let client = client();

        for input in [GARBAGE, "AAAA"] {
            let result = client.inspect_public_key(input.into());
            assert!(matches!(result, Err(ServerError::InvalidData)), "{input}");
        }
    }
}
