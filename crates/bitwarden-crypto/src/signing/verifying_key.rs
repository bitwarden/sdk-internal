//! A verifying key is the public part of a signature key pair. It is used to verify signatures.
//!
//! This implements the lowest layer of the signature module, verifying signatures on raw byte
//! arrays.

use ciborium::{Value, value::Integer};
use coset::{
    CborSerializable, MlDsaVariant, RegisteredLabel, RegisteredLabelWithPrivate,
    iana::{
        AkpKeyParameter, Algorithm, EllipticCurve, EnumI64, KeyOperation, KeyParameter, KeyType,
        OkpKeyParameter,
    },
};
use ml_dsa::{MlDsa44, signature::Verifier};

use super::{SignatureAlgorithm, ed25519_verifying_key, key_id, mldsa44_verifying_key};
use crate::{
    CoseKeyBytes, CoseKeyThumbprint, CryptoError,
    content_format::CoseKeyContentFormat,
    cose::{CoseKeyThumbprintExt, CoseSerializable, thumbprint_from_required_params},
    error::{EncodingError, SignatureError},
    keys::KeyId,
};

/// A `VerifyingKey` without the key id. This enum contains a variant for each supported signature
/// scheme.
pub(super) enum RawVerifyingKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    MlDsa44(Box<ml_dsa::VerifyingKey<MlDsa44>>),
}

/// A verifying key is a public key used for verifying signatures. It can be published to other
/// users, who can use it to verify that messages were signed by the holder of the corresponding
/// `SigningKey`.
pub struct VerifyingKey {
    pub(super) id: KeyId,
    pub(super) inner: RawVerifyingKey,
}

impl std::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key_suffix = match &self.inner {
            RawVerifyingKey::Ed25519(_) => "Ed25519",
            RawVerifyingKey::MlDsa44(_) => "MlDsa44",
        };
        let mut debug_struct = f.debug_struct(format!("VerifyingKey::{}", key_suffix).as_str());
        debug_struct.field("id", &self.id);
        match &self.inner {
            RawVerifyingKey::Ed25519(key) => {
                debug_struct.field("key", &hex::encode(key.to_bytes()));
            }
            RawVerifyingKey::MlDsa44(key) => {
                let encoded = key.encode();
                debug_struct.field("key", &hex::encode(encoded));
            }
        }
        debug_struct.finish()
    }
}

impl VerifyingKey {
    /// Returns the signature scheme used by the verifying key.
    pub fn algorithm(&self) -> SignatureAlgorithm {
        match &self.inner {
            RawVerifyingKey::Ed25519(_) => SignatureAlgorithm::Ed25519,
            RawVerifyingKey::MlDsa44(_) => SignatureAlgorithm::MlDsa44,
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
            RawVerifyingKey::MlDsa44(key) => {
                let sig = ml_dsa::Signature::<MlDsa44>::try_from(signature)
                    .map_err(|_| SignatureError::InvalidSignature)?;
                key.verify(data, &sig)
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
            RawVerifyingKey::MlDsa44(key) => coset::CoseKeyBuilder::new_mldsa_pub_key(
                MlDsaVariant::MlDsa44,
                key.encode().to_vec(),
            )
            .key_id((&self.id).into())
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
            (
                RegisteredLabel::Assigned(KeyType::AKP),
                RegisteredLabelWithPrivate::Assigned(Algorithm::ML_DSA_44),
            ) => Ok(VerifyingKey {
                id: key_id(&cose_key)?,
                inner: RawVerifyingKey::MlDsa44(Box::new(mldsa44_verifying_key(&cose_key)?)),
            }),
            _ => Err(EncodingError::UnsupportedValue(
                "COSE key type or algorithm",
            )),
        }
    }
}

impl CoseKeyThumbprintExt for VerifyingKey {
    fn thumbprint(&self) -> Result<CoseKeyThumbprint, CryptoError> {
        let params = match &self.inner {
            // https://datatracker.ietf.org/doc/rfc9679/
            RawVerifyingKey::Ed25519(key) => vec![
                (
                    KeyParameter::Kty.to_i64(),
                    Value::Integer(Integer::from(KeyType::OKP.to_i64())),
                ),
                (
                    OkpKeyParameter::Crv.to_i64(),
                    Value::Integer(Integer::from(EllipticCurve::Ed25519.to_i64())),
                ),
                // `x` is the compressed Ed25519 public key (see the note in `to_cose`).
                (
                    OkpKeyParameter::X.to_i64(),
                    Value::Bytes(key.to_bytes().to_vec()),
                ),
            ],
            // https://datatracker.ietf.org/doc/rfc9964/
            RawVerifyingKey::MlDsa44(key) => vec![
                (
                    KeyParameter::Kty.to_i64(),
                    Value::Integer(Integer::from(KeyType::AKP.to_i64())),
                ),
                (
                    KeyParameter::Alg.to_i64(),
                    Value::Integer(Integer::from(Algorithm::ML_DSA_44.to_i64())),
                ),
                (
                    AkpKeyParameter::Pub.to_i64(),
                    Value::Bytes(key.encode().to_vec()),
                ),
            ],
        };
        Ok(thumbprint_from_required_params(params))
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
    // Same key as `MLDSA44_VERIFYING_KEY` in `signing_key.rs`'s tests, kept in sync so both
    // modules pin the same underlying key.
    const MLDSA44_VERIFYING_KEY: &str = "a501070250e11a339366953128787c1b2c16b6945803382f048102205905205cc3620a551a0213972ad845e4930f4ecdfe1d10a81ffde8cdd1a0fffc38eefa3fd659028cad345c823074e870ffb9ed12e1d08a407db8f2431f2b75d3934e8a2662c033c8337aec1afdc1bb1babf185d709365a3057b41774dcf08e3877d4fdca2111b778ed53f6cf5b2d46d4a2427ee72c1c08a87e4e231794d8418513bae5e57d65428c41fa0b1031d6bc3b07a15f3349c4361a627c736d4e86fe3285e74277117f57df4bc53a98afcd55a77aee7e1b1465abb72e68ab2da897ceecfb8f7d4f0ced0dcf39506b31a46b795c8cee3ee6d789a1f8f7c35eb20eb17c6af5402954ec6eb41576eb2d65078b9755aca0e3af11f438df2a8abfb35d75b3fd151099735908f9b15a42f5211d4ea691014142adae9c9fdf0cf704bc4197d10f8f5f60be29abc805c6fa0f6192e4d12c8f7d50289e0ea796217f453730ca5af1ac3eb3c8ccc4bc161925806506160489a175a07bcf0f9323a4d05013117ba5f3c6d5bc6f6feadcfd093e40efbc19b8648cc8251d6d2faca5da7b506ec4b9e66b821c4176205b9ce0cd4c358b5e2a742c93b9ddb481feca10bb213925e1c661149c04e84a7809e440c190977cf015f12b6259581c368c70eec633985b78c1108f7ff42d1cb03d9ce957f705b871b57c3705ada6d6b386e647a3bacf846da4feb5c508bc4960c2d1f5378700b118fd2ea20db2790aafb7d39043bd2ab6f8902111a45fb181be8e83fa5a4c43e5d2d56797042f8d0c3e832857db0fccc61e7ea3616b70da0439eedf1a1a40196435c99b24e2ab07f8515272972faeafb2670ff66b237b00bf092da2de98a99ed4319498b4d8385aa68e36974b9c31d44b2dfebda78b3465b859296c63958cbcb587dd82e04c51986fdb9e0f3a2941ef1eac8d3b08c2fcd32ceb9dc434096c7f03e529c82132cd7e242a5668520baf00332a2de8a4f52420378350993bd35c573ba4f32e5ad89ddca1b7b3ddb0a21b0faa3674de2bdcb3519b86ed33a8939e6c7cbb9b9493279db28739b163916776bdcc40f7368000b5cefb3425b77dce84a957642319cb95226e30e119a4e455795b24e627b69881dc87084c3c1972fd170c87bcf4cc228beb4083a063e7a44c4fa8490f48457d12e4cf44b84ef41556e53599c5b4a030b4d07ee6594b6830ac0cb7823f908130fd6d2f3f9b5d65012f8e9abeeb74f4042a2a8c05fcb28f968f15f4230dfce034595141c770c200c1fd710e86d9b4d820ee0f015762526cb5a148e18874a385acef6f9efb77d43bc14936e8aa966dd53a1d2403a820f735fd60f5867570fa93ffae3214dc9ac93b2c191115a0045f71923249a10fdd8aa6ca35f6420fa1c80a867d7f54ef54b465f151de0b9a040c31d7373c81565d503cc1332dc6808533171ff2513a7139dad63b1848ba46f09255e81f7edab6208e62d17955aa43e27c74b5ed77b8d3c66ea50c478760e0db5c1b8970a22e74a29bd07bed0ba7e9c7a1866531889fa516ffd66c363d9558b2716d67809d85f16b4e18f456d5ec2343d08ea601da77676246c26432bfcd935c0d80a1e32fc41b380dff041a2629683540d5f2b9d9ef6101114242508c68987a44a0169bf8fbdabf1954bd54d745f1d66b7367848e43e0c94a6d88ccbdfd65333301d34d06d400e643e36c681c7f475b0026967d68e58af2fbf4800ca7aad6a43a3782b1d9452226ef881d50fcbb7b4df0c8c3b15ca80321cbb928fa8dce4048f01fc48121eaa1da0a954a6150c3d2e42add1b4f58910c2db0869a5481d469ef4bdccec3e7c0a21253fd19ce941b16808bf14fca6fec2b1ba7f771580235034e5ca95763721d6add9aa3914f476b37097ce67b000d5d";

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

    #[test]
    fn test_thumbprint_ed25519_vector() {
        let verifying_key = VerifyingKey::from_cose(&CoseKeyBytes::from(VERIFYING_KEY)).unwrap();
        assert_eq!(
            verifying_key.thumbprint().unwrap().to_hex(),
            "ea38af8eb96812daa5217a342946814921f0ebc74edaa1e9832cbc4daf9ba803"
        );
    }

    #[test]
    fn test_thumbprint_mldsa44_vector() {
        let verifying_key = VerifyingKey::from_cose(&CoseKeyBytes::from(
            hex::decode(MLDSA44_VERIFYING_KEY).unwrap(),
        ))
        .unwrap();
        assert_eq!(
            verifying_key.thumbprint().unwrap().to_hex(),
            "fb932d165a6ff31caf0537ecb3c267dcbdac69773de6b739211c00e68969e233"
        );
    }
}
