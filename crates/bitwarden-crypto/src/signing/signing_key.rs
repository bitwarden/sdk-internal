use std::pin::Pin;

use ciborium::{Value, value::Integer};
use coset::{
    CborSerializable, CoseKey, RegisteredLabel, RegisteredLabelWithPrivate,
    iana::{
        AkpKeyParameter, Algorithm, EllipticCurve, EnumI64, KeyOperation, KeyType, OkpKeyParameter,
    },
};
use ed25519_dalek::Signer;
use ml_dsa::{KeyGen as _, MlDsa65};
use rand::RngCore;

use super::{
    SignatureAlgorithm, ed25519_signing_key, key_id, mldsa65_signing_key,
    verifying_key::{RawVerifyingKey, VerifyingKey},
};
use crate::{
    CoseKeyBytes, CryptoKey,
    content_format::CoseKeyContentFormat,
    cose::CoseSerializable,
    error::{EncodingError, Result},
    keys::KeyId,
};

pub(crate) const ML_DSA_SEED_SIZE: usize = 32;

/// A `SigningKey` without the key id. This enum contains a variant for each supported signature
/// scheme.
#[derive(Clone)]
enum RawSigningKey {
    Ed25519(Pin<Box<ed25519_dalek::SigningKey>>),
    MlDsa65 {
        /// The seed is what's stored when serializing
        seed: Pin<Box<[u8; ML_DSA_SEED_SIZE]>>,
        /// The expanded signing key is derived from the seed
        signing_key: Pin<Box<ml_dsa::SigningKey<MlDsa65>>>,
        /// The verifying key is also derived from the seed
        verifying_key: Pin<Box<ml_dsa::VerifyingKey<MlDsa65>>>,
    },
}

/// A signing key is a private key used for signing data. An associated `VerifyingKey` can be
/// derived from it.
#[derive(Clone)]
pub struct SigningKey {
    pub(super) id: KeyId,
    inner: RawSigningKey,
}

// Note that `SigningKey` already implements ZeroizeOnDrop, so we don't need to do anything
// We add this assertion to make sure that this is still true in the future
// For any new keys, this needs to be checked
const _: fn() = || {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<ed25519_dalek::SigningKey>();
    assert_zeroize_on_drop::<ml_dsa::SigningKey<MlDsa65>>();
};
impl zeroize::ZeroizeOnDrop for SigningKey {}
impl CryptoKey for SigningKey {}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key_suffix = match &self.inner {
            RawSigningKey::Ed25519(_) => "Ed25519",
            RawSigningKey::MlDsa65 { .. } => "MlDsa65",
        };
        let mut debug_struct = f.debug_struct(format!("SigningKey::{}", key_suffix).as_str());
        debug_struct.field("id", &self.id);
        #[cfg(feature = "dangerous-crypto-debug")]
        match &self.inner {
            RawSigningKey::Ed25519(key) => debug_struct.field("key", &hex::encode(key.to_bytes())),
            RawSigningKey::MlDsa65 { seed, .. } => {
                debug_struct.field("seed", &hex::encode(*seed.as_ref()))
            }
        };
        debug_struct.finish()
    }
}

impl SigningKey {
    /// Makes a new signing key for the given signature scheme.
    pub fn make(algorithm: SignatureAlgorithm) -> Self {
        match algorithm {
            SignatureAlgorithm::Ed25519 => SigningKey {
                id: KeyId::make(),
                inner: RawSigningKey::Ed25519(Box::pin(ed25519_dalek::SigningKey::generate(
                    &mut rand::thread_rng(),
                ))),
            },
            SignatureAlgorithm::MlDsa65 => {
                let mut seed = [0u8; ML_DSA_SEED_SIZE];
                rand::thread_rng().fill_bytes(&mut seed);
                let key_pair = MlDsa65::key_gen_internal(&seed.into());
                SigningKey {
                    id: KeyId::make(),
                    inner: RawSigningKey::MlDsa65 {
                        seed: Box::pin(seed),
                        signing_key: Box::pin(key_pair.signing_key().clone()),
                        verifying_key: Box::pin(key_pair.verifying_key().clone()),
                    },
                }
            }
        }
    }

    pub(super) fn cose_algorithm(&self) -> Algorithm {
        match &self.inner {
            RawSigningKey::Ed25519(_) => Algorithm::EdDSA,
            RawSigningKey::MlDsa65 { .. } => Algorithm::ML_DSA_65,
        }
    }

    /// Derives the verifying key from the signing key. The key id is the same for the signing and
    /// verifying key, since they are a pair.
    pub fn to_verifying_key(&self) -> VerifyingKey {
        match &self.inner {
            RawSigningKey::Ed25519(key) => VerifyingKey {
                id: self.id.clone(),
                inner: RawVerifyingKey::Ed25519(key.verifying_key()),
            },
            RawSigningKey::MlDsa65 { verifying_key, .. } => VerifyingKey {
                id: self.id.clone(),
                inner: RawVerifyingKey::MlDsa65(verifying_key.clone()),
            },
        }
    }

    /// Signs the given byte array with the signing key.
    /// This should not be used directly other than for generating namespace separated signatures or
    /// signed objects.
    pub(super) fn sign_raw(&self, data: &[u8]) -> Vec<u8> {
        match &self.inner {
            RawSigningKey::Ed25519(key) => key.sign(data).to_bytes().to_vec(),
            RawSigningKey::MlDsa65 { signing_key, .. } => signing_key
                .sign_randomized(data, &[], &mut rand::thread_rng())
                .expect("ML-DSA signing should not fail with empty context")
                .encode()
                .as_slice()
                .to_vec(),
        }
    }
}

impl CoseSerializable<CoseKeyContentFormat> for SigningKey {
    /// Serializes the signing key to a COSE-formatted byte array.
    fn to_cose(&self) -> CoseKeyBytes {
        match &self.inner {
            RawSigningKey::Ed25519(key) => {
                coset::CoseKeyBuilder::new_okp_key()
                    .key_id((&self.id).into())
                    .algorithm(Algorithm::EdDSA)
                    .param(
                        OkpKeyParameter::D.to_i64(), // Signing key
                        Value::Bytes(key.to_bytes().into()),
                    )
                    .param(
                        OkpKeyParameter::Crv.to_i64(), // Elliptic curve identifier
                        Value::Integer(Integer::from(EllipticCurve::Ed25519.to_i64())),
                    )
                    .add_key_op(KeyOperation::Sign)
                    .add_key_op(KeyOperation::Verify)
                    .build()
                    .to_vec()
                    .expect("Signing key is always serializable")
                    .into()
            }
            RawSigningKey::MlDsa65 {
                seed,
                verifying_key,
                ..
            } => {
                // https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/
                let key = CoseKey {
                    key_id: (&self.id).into(),
                    kty: coset::RegisteredLabel::Assigned(KeyType::AKP),
                    alg: Some(coset::RegisteredLabelWithPrivate::Assigned(
                        Algorithm::ML_DSA_65,
                    )),
                    key_ops: vec![coset::RegisteredLabel::Assigned(KeyOperation::Sign)]
                        .into_iter()
                        .collect(),
                    params: vec![
                        (
                            coset::Label::Int(AkpKeyParameter::Priv.to_i64()),
                            Value::Bytes(seed.to_vec()),
                        ),
                        (
                            coset::Label::Int(AkpKeyParameter::Pub.to_i64()),
                            Value::Bytes(verifying_key.encode().to_vec()),
                        ),
                    ],
                    ..Default::default()
                };
                key.to_vec()
                    .expect("Signing key is always serializable")
                    .into()
            }
        }
    }

    /// Deserializes a COSE-formatted byte array into a signing key.
    fn from_cose(bytes: &CoseKeyBytes) -> Result<Self, EncodingError> {
        let cose_key =
            CoseKey::from_slice(bytes.as_ref()).map_err(|_| EncodingError::InvalidCoseEncoding)?;

        match (&cose_key.alg, &cose_key.kty) {
            (
                Some(RegisteredLabelWithPrivate::Assigned(Algorithm::EdDSA)),
                RegisteredLabel::Assigned(KeyType::OKP),
            ) => Ok(SigningKey {
                id: key_id(&cose_key)?,
                inner: RawSigningKey::Ed25519(Box::pin(ed25519_signing_key(&cose_key)?)),
            }),
            (
                Some(RegisteredLabelWithPrivate::Assigned(Algorithm::ML_DSA_65)),
                RegisteredLabel::Assigned(KeyType::AKP),
            ) => {
                let seed = mldsa65_signing_key(&cose_key)?;
                let key_pair = MlDsa65::key_gen_internal(&seed.into());
                let sk = key_pair.signing_key().clone();
                let vk = key_pair.verifying_key().clone();
                Ok(SigningKey {
                    id: key_id(&cose_key)?,
                    inner: RawSigningKey::MlDsa65 {
                        seed: Box::pin(seed),
                        signing_key: Box::pin(sk),
                        verifying_key: Box::pin(vk),
                    },
                })
            }
            _ => Err(EncodingError::UnsupportedValue(
                "COSE key type or algorithm",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MLDSA65_SIGNING_KEY: &str = "a601070250e5fd5c2a136b32259ea0610402544eed03383004810121582029285922d8938c8e3486669ce23de8e1a2bda530a5888db638d81e8fd1c00557205907a08a2853e233c469fda21e8f76259691df33e8fad7081c18184c539d57c2896bb4481ace7d5268f8e2c455211b878f9d58cb39fb84b7798df81798c0ae00214542b3b66c0dff621564fc0ae246380560c6b7b696022adb9b368cea7398b7d838e0e1cb1b846b6fbe5295040b6a5d9d51a7f97182bce728d582a16cad14d7dd238940e8e6d5fec48befad30dfeb56c739682789544417175da6aed8e5257cdea4877e423d284e76bb210d5b185d990393e188e5757eb3a980541a1c6141aaeaca98c5de147c553c8f45c35e9c3014f41abc701e2361edc3ff2f854ce100ea09ede1fb562dafd8a36e7d1f92b903bdc56f291dac6c919a975864a6bf68f3a702815a8fe0c9aefca77a89656e2c7fcf66e81fae39f530b4afcb1fbbe80a7bf300a4e2478e2a81998ee2570127e13e655a0a192ef510b3ca01fc6bcc3c434b7b5680dd795caf8008532c1dc5532d4dd8d354c1b3e13e1cceaa2c405c6a0d2bb39a0a608527d5129d29abab7f2e6d2be4b4a293668463b547058db1159c6bc41a82564f16cd65351bd275fadf09f3a28b06f9304f358c983d5f21d32b1e2be45d8c6b2d1d6a4317a4997a96b45fcab9b1e91432f90eaab8b2e4cdc002d526853927b71e8c32022935b3a1f358e76b4b836d00b7c0147353853ba53b78c71dd5d4b72fcb0224ebc02e424b258855af7435daa7de97291287705097150b11a8282a42cac605f3145655839dd4fcb890eb3e793e4a39cff48e8ab2c7450629a0e09fac1c1b10cb6e4c61b4f247386b3f7daaca90201431aa49120dcafbb3ca597f0917b4c92e65345bf8a08ea4496813f8e38c50554ad120e26004f8acf75e381bb43a9f87c806ef05a41327808bf34deda10fefc95868a4d50739f1aa217f51aef699884577db0dd3c01f467e192635fdb126fad0015fd6e56a1144d0adfa09f786acebc4c17e21c876f5e3b7c5925c044bd7496ad7bff58d232bf1cd5aa67a42d83f0fc30d63103cea522f88b2f4ee51bb601db47a348a6d96d5ec2020b0f7dbce5796e29aff8dec0c9c5b9a1ac40df48971b2e0bf4b84ce2584a09bbe50a904d74a9fa79ee6b452d03047c7310391703557e7ea4c3f80bb228027d8b6989553c8f96707419135e8da333f7142df631b164251dcb7238711fad3d1545edb7c96a13ba4dbef1c415ebbc6a2e45fdaabc16f20bd1d33e9e1e48f9c6c39af39c753f5cf320691779d73f56c929aece87b534b4586781c0fb177a21c4e6f974142b366ef24874baf080139d00c57a13eeeac3cb035c067dffbeac89aa186610087f56660d897d25ea0ac2ff04a4862657e25a61c7716d325ed90f3df0f82381083c9e08f236a2f5083b6a56181cedaaac9a640db7349e430b2e80c8aaa8eb1562415df2c22da9a42575f3755740eae00b8ebfc7a799a3b88dd037027ec0fd2d7bb32abb73c1bfca6c7bbe0fe6706c5cfa66b9b140c2200bbb3a243857f40a9521aa31c882dd6bc68c894bb1e29620e93762974b50e8e41dc3f536cd46cc81b7d87146a88078921feeb15b704f83dc921185f01d2ebb65518ce928192a8d0cda084b2c0ac84754998c6301bef1ed04a3d73606dddf1f4d9e9b2b0a9345fddd98e68caff0be2b39e8b4da2d5d5b0411c385d905618efbeba8517b2e083c1f4c2814802f8f937ac2badaa2692b894529369a70e35f8f00367b672c8c9ed17a401bedceeb8dd613e5f0b0e429e842dc2830a17e189902c8d602c8ab67ce9424ccf092f4f2d8b1768f93f686bdacbcd4fcbbf25fecc0c838580bdf895c303cc265f565a7b02f8a3267dc9561a86e38bec2118d5c6235e9946f1080d7dcaddc066052fc3fdebd678242af0d1daa4eb11702b1f2378ba6f0b1c11365f80e81ab43d11a4d5a686d5b4cfe1513bd17a22d3fd3e223a152d7052fb700f25766341c739140495d0e9ce29871531b7731316e6210c9d92f434619a2e35c8a37534d5281175da7bd9abc670b40354be3f114ccadb6eee34d1d8b90bb071a7c2891dc69f88319ec9c1b74e11cfe2cf0411ce3916d2167016abf5bcd65f83fbe2b86d932d2753bc20aa4860f1bae224de2d424c3d065e803aa7383ccfd1a3bd79687ae817d1d35f161628d61cbd167284cbbdbef29bd8ecc33a4c73c6858bdb1f57b1b9012fb163b6c2ba68c20303426982e92bc3e4e998567d841ec0daeadac2f76b30b6a186d076958c5dedd54b07c8ea486e5f0b8cd4aa98021924e27b0ea13906d5fde63d87b079070dc0b4e6a1ccd8f35d98152e08d4bcc18be5d6e50556eea631e8e7cf11fbb670dfde59c58c9e853f0428061607ea20cd0b2493b38922e460d2e4bf454547a8f2f53e888a2c4c0da62a75f986232ec3f227b195d1257ce04ca832db477d3ab2bde66b973eb357e5e2c272794d5fa18deba3843db6ae21d27ef2d01cbe6a0e46d6aa885de4fd940d12ac8f6124df0cb3c4da75aff1c90401998052ddf1bea5db2166e724c93d450720bfe4a41036e9926267d80cd40f4b7c2b956d160b5cae63d806740d6a6a2871740c601c6ad7f7a50faf6fa524a4a76f821387bd41271e623a9f005103067d5c07d6c6babd694de4f2cc8492fa7c699777941177031e0a01adb299098c99d500f2babf5f8d6c3d51bf28a58abe630f6aa6faa33d792f38bd5c90ce728d8f537ed03fe1e1b7fdc017aaaadd413ed26f56c7586d73b4894d3eafe69ee08b13f6031f7d0f7a299193465d234841d0b4030d9eaeef735eb2112d0a10a59b";
    const MLDSA65_VERIFYING_KEY: &str = "a501070250e5fd5c2a136b32259ea0610402544eed033830048102205907a08a2853e233c469fda21e8f76259691df33e8fad7081c18184c539d57c2896bb4481ace7d5268f8e2c455211b878f9d58cb39fb84b7798df81798c0ae00214542b3b66c0dff621564fc0ae246380560c6b7b696022adb9b368cea7398b7d838e0e1cb1b846b6fbe5295040b6a5d9d51a7f97182bce728d582a16cad14d7dd238940e8e6d5fec48befad30dfeb56c739682789544417175da6aed8e5257cdea4877e423d284e76bb210d5b185d990393e188e5757eb3a980541a1c6141aaeaca98c5de147c553c8f45c35e9c3014f41abc701e2361edc3ff2f854ce100ea09ede1fb562dafd8a36e7d1f92b903bdc56f291dac6c919a975864a6bf68f3a702815a8fe0c9aefca77a89656e2c7fcf66e81fae39f530b4afcb1fbbe80a7bf300a4e2478e2a81998ee2570127e13e655a0a192ef510b3ca01fc6bcc3c434b7b5680dd795caf8008532c1dc5532d4dd8d354c1b3e13e1cceaa2c405c6a0d2bb39a0a608527d5129d29abab7f2e6d2be4b4a293668463b547058db1159c6bc41a82564f16cd65351bd275fadf09f3a28b06f9304f358c983d5f21d32b1e2be45d8c6b2d1d6a4317a4997a96b45fcab9b1e91432f90eaab8b2e4cdc002d526853927b71e8c32022935b3a1f358e76b4b836d00b7c0147353853ba53b78c71dd5d4b72fcb0224ebc02e424b258855af7435daa7de97291287705097150b11a8282a42cac605f3145655839dd4fcb890eb3e793e4a39cff48e8ab2c7450629a0e09fac1c1b10cb6e4c61b4f247386b3f7daaca90201431aa49120dcafbb3ca597f0917b4c92e65345bf8a08ea4496813f8e38c50554ad120e26004f8acf75e381bb43a9f87c806ef05a41327808bf34deda10fefc95868a4d50739f1aa217f51aef699884577db0dd3c01f467e192635fdb126fad0015fd6e56a1144d0adfa09f786acebc4c17e21c876f5e3b7c5925c044bd7496ad7bff58d232bf1cd5aa67a42d83f0fc30d63103cea522f88b2f4ee51bb601db47a348a6d96d5ec2020b0f7dbce5796e29aff8dec0c9c5b9a1ac40df48971b2e0bf4b84ce2584a09bbe50a904d74a9fa79ee6b452d03047c7310391703557e7ea4c3f80bb228027d8b6989553c8f96707419135e8da333f7142df631b164251dcb7238711fad3d1545edb7c96a13ba4dbef1c415ebbc6a2e45fdaabc16f20bd1d33e9e1e48f9c6c39af39c753f5cf320691779d73f56c929aece87b534b4586781c0fb177a21c4e6f974142b366ef24874baf080139d00c57a13eeeac3cb035c067dffbeac89aa186610087f56660d897d25ea0ac2ff04a4862657e25a61c7716d325ed90f3df0f82381083c9e08f236a2f5083b6a56181cedaaac9a640db7349e430b2e80c8aaa8eb1562415df2c22da9a42575f3755740eae00b8ebfc7a799a3b88dd037027ec0fd2d7bb32abb73c1bfca6c7bbe0fe6706c5cfa66b9b140c2200bbb3a243857f40a9521aa31c882dd6bc68c894bb1e29620e93762974b50e8e41dc3f536cd46cc81b7d87146a88078921feeb15b704f83dc921185f01d2ebb65518ce928192a8d0cda084b2c0ac84754998c6301bef1ed04a3d73606dddf1f4d9e9b2b0a9345fddd98e68caff0be2b39e8b4da2d5d5b0411c385d905618efbeba8517b2e083c1f4c2814802f8f937ac2badaa2692b894529369a70e35f8f00367b672c8c9ed17a401bedceeb8dd613e5f0b0e429e842dc2830a17e189902c8d602c8ab67ce9424ccf092f4f2d8b1768f93f686bdacbcd4fcbbf25fecc0c838580bdf895c303cc265f565a7b02f8a3267dc9561a86e38bec2118d5c6235e9946f1080d7dcaddc066052fc3fdebd678242af0d1daa4eb11702b1f2378ba6f0b1c11365f80e81ab43d11a4d5a686d5b4cfe1513bd17a22d3fd3e223a152d7052fb700f25766341c739140495d0e9ce29871531b7731316e6210c9d92f434619a2e35c8a37534d5281175da7bd9abc670b40354be3f114ccadb6eee34d1d8b90bb071a7c2891dc69f88319ec9c1b74e11cfe2cf0411ce3916d2167016abf5bcd65f83fbe2b86d932d2753bc20aa4860f1bae224de2d424c3d065e803aa7383ccfd1a3bd79687ae817d1d35f161628d61cbd167284cbbdbef29bd8ecc33a4c73c6858bdb1f57b1b9012fb163b6c2ba68c20303426982e92bc3e4e998567d841ec0daeadac2f76b30b6a186d076958c5dedd54b07c8ea486e5f0b8cd4aa98021924e27b0ea13906d5fde63d87b079070dc0b4e6a1ccd8f35d98152e08d4bcc18be5d6e50556eea631e8e7cf11fbb670dfde59c58c9e853f0428061607ea20cd0b2493b38922e460d2e4bf454547a8f2f53e888a2c4c0da62a75f986232ec3f227b195d1257ce04ca832db477d3ab2bde66b973eb357e5e2c272794d5fa18deba3843db6ae21d27ef2d01cbe6a0e46d6aa885de4fd940d12ac8f6124df0cb3c4da75aff1c90401998052ddf1bea5db2166e724c93d450720bfe4a41036e9926267d80cd40f4b7c2b956d160b5cae63d806740d6a6a2871740c601c6ad7f7a50faf6fa524a4a76f821387bd41271e623a9f005103067d5c07d6c6babd694de4f2cc8492fa7c699777941177031e0a01adb299098c99d500f2babf5f8d6c3d51bf28a58abe630f6aa6faa33d792f38bd5c90ce728d8f537ed03fe1e1b7fdc017aaaadd413ed26f56c7586d73b4894d3eafe69ee08b13f6031f7d0f7a299193465d234841d0b4030d9eaeef735eb2112d0a10a59b";
    const MLDSA65_SIGNED_DATA_RAW: &str = "35bb3d152543641c8a97149d0a9ef23c8894b37b359265296df7422099b62e24f03d56384e3aa001ca265f6bcd7762606a42df879265f36e0f1cc7401be74a76f68e1de53cf1cfb5f67deca1c78fe423ef495ef999dcf1f88e1ecc3f1940e177888f2724906ab8a3402b393d5fd964e288cf54c032ec4e2a0550f8d741e765f93d35801939c54c72999e23e0efd8596114e9c35decd79e225f383a6d8e704ac2003e5e37ea7b71431bce12e2750e40d531c0c175152c6657d2eb60b4b87f9b22a51b44a3149f4d2486b626c4a99f73741ed16a6ff9de2550980c4b34e014070dca6a78e815a8da3ee41f63eb6d8c81906c504f9e75995ad4dd0d55b84600fe42b8c5b3e5762e1e8b99fc3dda8c384837b6bf1b08b0514736267e257d5159b9bbf3d6c6fc920d98467905f91c9b4c76dc141d3289e05ead53b45e9039c0f1107de71e321c2c01674449b1fd945b5bb91b3fcd38d16182b94f948bc138441308300229a6f08dce786414b854d684786f5607cae91e0cf68753d42064c03322432cd64b1946f15ff2c29013b721d17b85dab3501de36b8f9b28831f9522319d1df791a5a635101f2a276c4716ad9e343b60b94b9ddff933770b35ea2770b2d9e78633a4a224bebc9beebd02b1ce59705016a7ad3e4510f4b8b61a2103014c907f7a7ec06219f07b40e2418d74707ac7bf26a8103cb527599a28a9b23ae685bcc46d3acb02104a815aaed18ef4065e2aa74b2100080c6eb3236000f96c05776a1ec891f4c49098fe329ee32993cf2d4b787c216a5b8684640a9762a1d7729f9fed04f533a522c4f77ae7173dd108b956f822ce59fb5874511e6ff42435b3bd0c500958ae49843019a5cba1f8ddd5f2e7938eb00c083f4d421a76fd1af00afbe9ad79689b05df7317c7f9d4430a178a46a6f6d0494e28052a009df7848ede31e3566221f23545f4b5c30ff7e0d2735566d5cbcdf2189fa443072fed5db272890e8611d5e61369231d057cc91ad95b0f83161c4c6698cc98cabda8d38035415e886078a04bb415d7c5eab9edf362a5ff045255094a08fc46034a98be562c1d1ab6f5b4cb148e78d66e04d09f80c67e35c3f13ecaff2267cad95dab869fe1aa81c605f4de3bca985db0035fa0023b25a82d88da94bd29f8c465a462e9bc9f0a47c8ea073f2e019db8cc07d1c55bc165f3fcba3550e7575b8913d178b7285fb0135b71ff190eaeed04307df3e87be913f9c8260aae61c6e700650d46b8d82295a03bfa0c85c424e2abeb96a4c6662c94f29beca4a925de72601ee2cc56dfa9190ba0e7012ee5e126634aa5348607b2a92d28472a67cc34937f34bb8275af40daba373791331220462f4c6fad613770581186153d227a78051c10f556eaad66c161c79b51385325cb6fd4de0ed28176bc1aec803da2835165a031b1808f9b328230e268b26e2d7a285637eeefb85871322736dc83b3ca16eb4624ebd4d9c2bb8a2ba4dbb9d539785d153847c504271dff81fb08a4f193f37acb58bfecdaffb1f7e896c88ca2e92b2dfbbd2a547b29d077f2d7d332d265eea4f80980b3b2c0b0131a5aa1e0b46efdc59e0e841ae050a2a6b140673ef04c9246361ca3dcbad2b56c1d05a3c83ca8bcbfac15428c84ec479b30440c897ed9e9310e973fe87e97ea820aaf4d96c430d6f25fa599fa16233050c81de6097e3eeefa83e1cebf3df21ffed9c25d81b968ac1022eb298427d7c3c99605e76c2037ab80ed609e10154068fb26b24f2a231a0207ace585d56066f40bdacba71912966015b4750d18a80b55728020050b044ee5596176ca6ee37a2eaf3693859e4f1fe2355390530ee6cf356627540dca7044644bf713775a21324700214fe554435669e5f197b67d678ce54911de5edcf0072fc4550f65689ffe95ed2efc48f8d2ecad0c0a1cc871a9d154a27d5aac6760999ef0fcbc560e5a7bc56c110d5430875b88cb53a855695f415b5c7c7cd2e5562c0f9a201977bef7e6ec5cb8981a8bb7f316abbc11acf4f41873378e429371009a425064ae0f7c5845c140fbbd557b859f80c75e88fbe7b3477ef414e12692985136a50681fa485db31d714582855fe5c3c045ea1addd5caf89be2bfecea2043a7ce602387a410206acdf3a88b13ab60fbe1d6dc77bae95365d9ab48980f40d6606209a2b00be1386e846b44a0bcf4e315ea21906b2e1fa38b8d4b6071691653e488f3b5e5f11d8436c49c31a1d41044916e060b72c5acf83a063ed4872b6a743f513d5eb66c8cf9397f7cc1e0b3a60c6b554003fdbba8fdf2d1c6fc67b22b22d0e54d75c3a6b8ddd97cb45356061ba6dea9b8b599247d454be9d9b2e658f9bb5a16b139ae3b4a690214dbff6761ccbb3e3200e0759d1a2b5991d7ea52e3f631cc53fe1f575bc697acb2e7c2492df35aafdd9467146271ce6d92b929ac462aa0438927b9a56662be18f744d8fdfb7e89392f75d1c242297390f1d43d1f380ee69bafd1b61ce65650353162f0c2d3fe72855118ff546995f0b1460c54fc8a73846f089648da06924d827fa351e06ac4d4c516cc9ad21c9b4994fb9846a0e0b705543d707a81fc0746e137eabaf4c9ff4013c050d268a026746da07084a3baf969e1f8d6be5a2e239e1b30a3274f6e02c5c9a24264d54a465a5f64936ae378af3d957f7749a0f0e9dcf444c6f93ae84cceac1c2821a83fb401ae4f562e9cc7431dbca4f52580351f3bbac98392931abd3b609d5d1f4e2e616145835f0d97b14773d50fd499d4f932ce9adb325527f7fad44ad061913274fb45fcdbd26daf8c7204cab05aa5d60f06f51b0b88f70cda1e6cf91e7e747501a4e5a3c29719ddcb2fad2e942c83a60665bd9fb56821346ae2c6423b2ee45dab345416a277fd835c8d84e0f2981b4fca02854e452a0c6cc87a347f91fff43326100772675cb53f6792499fb91e722ae6f7bd872d0bfac9ccf4d52de806980a1f4fbc40f2b57c327d947ff44dfebdd944b20cb3e49568f3d9d839e435a18d77fc068fe07e9a43d125425992c60e9816c0f6159b016b5c2ead177fdb8f7eeb3e382e72e2dc1a2618c4c94c2e65639fd4861834116242899b6d5779cd70af3ebdd97f2f91a007b62a99dd8975a7c4e46b9b91f0a514080ddef665a8bcb2dc1710d2caa453b12d38c17fcee92cbdcff33dd549540869ef15921a1faedf89187d41959c83ae8e4a438f1ca6718ae9b667543cc5e95bbced1114c2c6b8029e303d24ed21633268677d2b53806796a4641c3541f1336152f2b6971d20576ca947d8ebd96e1799a7c405e20e7be347e724cac83b10d90cb7c85927db3c5c2c3d68beed79cc6825c24afc47435256599fbdadbaf3ae341fc6a8f616e2f1b491129627eb66555a9e1208c647a91c00183557618b023533d40463191bb3ce6ddc3415cdfa13e16c47b44d3ebcd45b295a505f02f6bd86f6de4c39c174421f680fa39fcf6b9ad0d8a643a9b15bce78bed27b008f1da8158025852f04f6c9b1e1d337c7ee0d7cbff7395db421efcbcdb8ba21735d841ab0f93e55ce4ffadb3e8ebe30f9a3be63b406ac4e5cdef8d3d25aa91cdc19794f6a56f50557297a714c76b3f217517f0b70a4cbf4c51fc8f93c6cc8002279879752204601d833cee84fed436f0507b11ff29cbc661ea807732a5cd9642ea8d49daa4280159772dcf94a1bd2e04e9c4acea9ddd70c9c99776cb49d20d392355c23d767a17a0c330a1fab41a8b05bf1842f5783c465f4cf1212f873ca28ea4a2b9908c9c30009766e4cf4f25c9ce36a37582c86733d894166627631c65aa27db99778d13ea1b288055e7d9ba410976593884c491f53235574f86fce5c9e900953b026848d52e89163e3025625a2f1aec40d4f7e37862d199f5407fa589647a13718f930ffb14cfa28407a3000de7b9adc68e624d95ba6c2af64fcdf387e5ba75c5a9c06b1784fea6b566084e2b242437ad55493b57aea73ea4e591e79f8da3cdc1bf468d94285c9dc1f64da05f96eb09404351954d6078267ef780556c4218c4f1ff932c5ad69af0fc09c9d2ebdd56a435331360ee27fed77dbba91c30ee48823a80b63fb93bd3f548b2ae4c6113bf5a4ea4fc6a770766467098b06538a5d99fa447e28801616a6501e862924fd808ca57d3f3ea8a8e879b3160fea0718d1f60dadd46e0c66e30a36ed1bd0c5ec8d1e1e63c9cd42f646f3018687ad0695c6c2bf237b403539596c966ed4ea29eda9c085e5c2a880eda2c64f295b697892709044e628b13c91a87d757825bb274ffa3da9ee3c62ce5829727d3d148a4a2e620f8f5c104de69b937f050926a6a776a2e2758bd5314c64d560a1c3b659a1934e01e69d612c2ce2ff8fc70342d155139eb746506c3acbdd1e85ee8cd5890e50462c893f3c9d8a2b64a05e0ad476b9b0be301890daaabac035db95f7f27aec53dec44984c1309a1056c4daf370daf0329883e6beaa8d1ea8d559d5df004397e167daf209ab84afbba5c06bacfba26e6d71a002eba7e3a0ce4ed4b1289b4dd4f4fad0235687960f6f9fd1263265b037a4f7186aa2c3b08ea1cff65b9af2b7c8fef2ce7b75c7c7353effd1a21d2a335170b6f8151a1b3c75ae17447abb1a26a7ca379baad3dfe0f80b13447c9fa8b5d4ed0000000000000000000000000000000000000000050b0f131a23";

    #[test]
    #[ignore = "Manual test to verify debug format"]
    fn test_key_debug() {
        let key = SigningKey::make(SignatureAlgorithm::Ed25519);
        println!("{:?}", key);
        let verifying_key = key.to_verifying_key();
        println!("{:?}", verifying_key);

        let key = SigningKey::make(SignatureAlgorithm::MlDsa65);
        println!("{:?}", key);
        let verifying_key = key.to_verifying_key();
        println!("{:?}", verifying_key);
    }

    #[test]
    fn test_cose_roundtrip_encode_signing() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
        let cose = signing_key.to_cose();
        let parsed_key = SigningKey::from_cose(&cose).unwrap();

        assert_eq!(signing_key.to_cose(), parsed_key.to_cose());
    }

    #[test]
    fn test_sign_rountrip() {
        let signing_key = SigningKey::make(SignatureAlgorithm::Ed25519);
        let signature = signing_key.sign_raw("Test message".as_bytes());
        let verifying_key = signing_key.to_verifying_key();
        assert!(
            verifying_key
                .verify_raw(&signature, "Test message".as_bytes())
                .is_ok()
        );
    }

    #[test]
    #[ignore = "Run manually to generate ML-DSA-65 test vectors"]
    fn generate_test_vectors_mldsa65() {
        let signing_key = SigningKey::make(SignatureAlgorithm::MlDsa65);
        let verifying_key = signing_key.to_verifying_key();
        let raw_signature = signing_key.sign_raw(b"Test message");

        println!(
            "const MLDSA65_SIGNING_KEY: &str = \"{}\";",
            hex::encode(signing_key.to_cose().as_ref())
        );
        println!(
            "const MLDSA65_VERIFYING_KEY: &str = \"{}\";",
            hex::encode(verifying_key.to_cose().as_ref())
        );
        println!(
            "const MLDSA65_SIGNED_DATA_RAW: &str = \"{}\";",
            hex::encode(raw_signature.as_slice())
        );
    }

    #[test]
    fn test_mldsa65_test_vectors() {
        let signing_key = SigningKey::from_cose(&CoseKeyBytes::from(hex::decode(MLDSA65_SIGNING_KEY).unwrap())).unwrap();
        let verifying_key = signing_key.to_verifying_key();
        assert_eq!(
            verifying_key.to_cose().as_ref(),
            &hex::decode(MLDSA65_VERIFYING_KEY).unwrap()[..]
        );
        verifying_key.verify_raw(&hex::decode(MLDSA65_SIGNED_DATA_RAW).unwrap(), b"Test message").unwrap();
    }

    #[test]
    fn test_cose_roundtrip_encode_signing_mldsa65() {
        let signing_key = SigningKey::make(SignatureAlgorithm::MlDsa65);
        let cose = signing_key.to_cose();
        let parsed_key = SigningKey::from_cose(&cose).unwrap();

        assert_eq!(signing_key.to_cose(), parsed_key.to_cose());
    }

    #[test]
    fn test_sign_roundtrip_mldsa65() {
        let signing_key = SigningKey::make(SignatureAlgorithm::MlDsa65);
        let signature = signing_key.sign_raw(b"Test message");
        let verifying_key = signing_key.to_verifying_key();
        assert!(
            verifying_key
                .verify_raw(&signature, b"Test message")
                .is_ok()
        );
    }
}
