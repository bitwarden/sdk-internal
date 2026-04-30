use std::pin::Pin;

use ciborium::{Value, value::Integer};
use coset::{
    CborSerializable, CoseKey, MlDsaVariant, RegisteredLabel, RegisteredLabelWithPrivate,
    iana::{
        AkpKeyParameter, Algorithm, EllipticCurve, EnumI64, KeyOperation, KeyType, OkpKeyParameter,
    },
};
use ed25519_dalek::Signer;
use hybrid_array::Array;
use ml_dsa::{B32, KeyGen, MlDsa44, signature::Keypair};
use rand::Rng;

use super::{
    SignatureAlgorithm, ed25519_signing_key, key_id, mldsa_seed,
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
    MlDsa44 {
        seed: Pin<Box<B32>>,
        signing_key: Pin<Box<ml_dsa::ExpandedSigningKey<MlDsa44>>>,
        verifying_key: Box<ml_dsa::VerifyingKey<MlDsa44>>,
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
    assert_zeroize_on_drop::<ml_dsa::ExpandedSigningKey<MlDsa44>>();
};
impl zeroize::ZeroizeOnDrop for SigningKey {}
impl CryptoKey for SigningKey {}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key_suffix = match &self.inner {
            RawSigningKey::Ed25519(_) => "Ed25519",
            RawSigningKey::MlDsa44 { .. } => "MlDsa44",
        };
        let mut debug_struct = f.debug_struct(format!("SigningKey::{}", key_suffix).as_str());
        debug_struct.field("id", &self.id);
        #[cfg(feature = "dangerous-crypto-debug")]
        match &self.inner {
            RawSigningKey::Ed25519(key) => debug_struct.field("key", &hex::encode(key.to_bytes())),
            RawSigningKey::MlDsa44 { seed, .. } => {
                debug_struct.field("seed", &hex::encode(seed.to_vec()))
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
                    &mut rand::rng(),
                ))),
            },
            SignatureAlgorithm::MlDsa44 => {
                // This is heap allocated from the start, so will be zeroized on drop
                let mut seed = Box::pin(Array::from([0u8; 32]));
                rand::rng().fill_bytes(&mut seed);

                let kp = MlDsa44::from_seed(&seed);
                SigningKey {
                    id: KeyId::make(),
                    inner: RawSigningKey::MlDsa44 {
                        seed,
                        signing_key: Box::pin(kp.signing_key().clone()),
                        verifying_key: Box::new(kp.verifying_key().clone()),
                    },
                }
            }
        }
    }

    pub(super) fn cose_algorithm(&self) -> Algorithm {
        match &self.inner {
            RawSigningKey::Ed25519(_) => Algorithm::EdDSA,
            RawSigningKey::MlDsa44 { .. } => Algorithm::ML_DSA_44,
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
            RawSigningKey::MlDsa44 { verifying_key, .. } => VerifyingKey {
                id: self.id.clone(),
                inner: RawVerifyingKey::MlDsa44(Box::new(*verifying_key.clone())),
            },
        }
    }

    /// Signs the given byte array with the signing key.
    /// This should not be used directly other than for generating namespace separated signatures or
    /// signed objects.
    pub(super) fn sign_raw(&self, data: &[u8]) -> Vec<u8> {
        match &self.inner {
            RawSigningKey::Ed25519(key) => key.sign(data).to_bytes().to_vec(),
            RawSigningKey::MlDsa44 { signing_key, .. } => signing_key
                .sign_randomized(data, &[], &mut rand::rng())
                .expect("Empty ML-DSA context must be accepted")
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
                    .build()
                    .to_vec()
                    .expect("Signing key is always serializable")
                    .into()
            }
            RawSigningKey::MlDsa44 {
                seed,
                verifying_key,
                ..
            } => coset::CoseKeyBuilder::new_mldsa_pub_key(
                MlDsaVariant::MlDsa44,
                verifying_key.encode().to_vec(),
            )
            .key_id((&self.id).into())
            .param(AkpKeyParameter::Priv.to_i64(), Value::Bytes(seed.to_vec()))
            .add_key_op(KeyOperation::Sign)
            .build()
            .to_vec()
            .expect("Signing key is always serializable")
            .into(),
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
                Some(RegisteredLabelWithPrivate::Assigned(Algorithm::ML_DSA_44)),
                RegisteredLabel::Assigned(KeyType::AKP),
            ) => {
                let seed = mldsa_seed(&cose_key)?;
                let kp = MlDsa44::from_seed(&seed);
                Ok(SigningKey {
                    id: key_id(&cose_key)?,
                    inner: RawSigningKey::MlDsa44 {
                        seed: Box::pin(seed),
                        signing_key: Box::pin(kp.signing_key().clone()),
                        verifying_key: Box::new(kp.verifying_key().clone()),
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

    const MLDSA44_SIGNING_KEY: &str = "a601070250e11a339366953128787c1b2c16b6945803382f048101205905205cc3620a551a0213972ad845e4930f4ecdfe1d10a81ffde8cdd1a0fffc38eefa3fd659028cad345c823074e870ffb9ed12e1d08a407db8f2431f2b75d3934e8a2662c033c8337aec1afdc1bb1babf185d709365a3057b41774dcf08e3877d4fdca2111b778ed53f6cf5b2d46d4a2427ee72c1c08a87e4e231794d8418513bae5e57d65428c41fa0b1031d6bc3b07a15f3349c4361a627c736d4e86fe3285e74277117f57df4bc53a98afcd55a77aee7e1b1465abb72e68ab2da897ceecfb8f7d4f0ced0dcf39506b31a46b795c8cee3ee6d789a1f8f7c35eb20eb17c6af5402954ec6eb41576eb2d65078b9755aca0e3af11f438df2a8abfb35d75b3fd151099735908f9b15a42f5211d4ea691014142adae9c9fdf0cf704bc4197d10f8f5f60be29abc805c6fa0f6192e4d12c8f7d50289e0ea796217f453730ca5af1ac3eb3c8ccc4bc161925806506160489a175a07bcf0f9323a4d05013117ba5f3c6d5bc6f6feadcfd093e40efbc19b8648cc8251d6d2faca5da7b506ec4b9e66b821c4176205b9ce0cd4c358b5e2a742c93b9ddb481feca10bb213925e1c661149c04e84a7809e440c190977cf015f12b6259581c368c70eec633985b78c1108f7ff42d1cb03d9ce957f705b871b57c3705ada6d6b386e647a3bacf846da4feb5c508bc4960c2d1f5378700b118fd2ea20db2790aafb7d39043bd2ab6f8902111a45fb181be8e83fa5a4c43e5d2d56797042f8d0c3e832857db0fccc61e7ea3616b70da0439eedf1a1a40196435c99b24e2ab07f8515272972faeafb2670ff66b237b00bf092da2de98a99ed4319498b4d8385aa68e36974b9c31d44b2dfebda78b3465b859296c63958cbcb587dd82e04c51986fdb9e0f3a2941ef1eac8d3b08c2fcd32ceb9dc434096c7f03e529c82132cd7e242a5668520baf00332a2de8a4f52420378350993bd35c573ba4f32e5ad89ddca1b7b3ddb0a21b0faa3674de2bdcb3519b86ed33a8939e6c7cbb9b9493279db28739b163916776bdcc40f7368000b5cefb3425b77dce84a957642319cb95226e30e119a4e455795b24e627b69881dc87084c3c1972fd170c87bcf4cc228beb4083a063e7a44c4fa8490f48457d12e4cf44b84ef41556e53599c5b4a030b4d07ee6594b6830ac0cb7823f908130fd6d2f3f9b5d65012f8e9abeeb74f4042a2a8c05fcb28f968f15f4230dfce034595141c770c200c1fd710e86d9b4d820ee0f015762526cb5a148e18874a385acef6f9efb77d43bc14936e8aa966dd53a1d2403a820f735fd60f5867570fa93ffae3214dc9ac93b2c191115a0045f71923249a10fdd8aa6ca35f6420fa1c80a867d7f54ef54b465f151de0b9a040c31d7373c81565d503cc1332dc6808533171ff2513a7139dad63b1848ba46f09255e81f7edab6208e62d17955aa43e27c74b5ed77b8d3c66ea50c478760e0db5c1b8970a22e74a29bd07bed0ba7e9c7a1866531889fa516ffd66c363d9558b2716d67809d85f16b4e18f456d5ec2343d08ea601da77676246c26432bfcd935c0d80a1e32fc41b380dff041a2629683540d5f2b9d9ef6101114242508c68987a44a0169bf8fbdabf1954bd54d745f1d66b7367848e43e0c94a6d88ccbdfd65333301d34d06d400e643e36c681c7f475b0026967d68e58af2fbf4800ca7aad6a43a3782b1d9452226ef881d50fcbb7b4df0c8c3b15ca80321cbb928fa8dce4048f01fc48121eaa1da0a954a6150c3d2e42add1b4f58910c2db0869a5481d469ef4bdccec3e7c0a21253fd19ce941b16808bf14fca6fec2b1ba7f771580235034e5ca95763721d6add9aa3914f476b37097ce67b000d5d215820d6b3615887fa819d9b215654a2494c714a64d4b0c9997149ee853c2bc0a415f3";
    const MLDSA44_VERIFYING_KEY: &str = "a501070250e11a339366953128787c1b2c16b6945803382f048102205905205cc3620a551a0213972ad845e4930f4ecdfe1d10a81ffde8cdd1a0fffc38eefa3fd659028cad345c823074e870ffb9ed12e1d08a407db8f2431f2b75d3934e8a2662c033c8337aec1afdc1bb1babf185d709365a3057b41774dcf08e3877d4fdca2111b778ed53f6cf5b2d46d4a2427ee72c1c08a87e4e231794d8418513bae5e57d65428c41fa0b1031d6bc3b07a15f3349c4361a627c736d4e86fe3285e74277117f57df4bc53a98afcd55a77aee7e1b1465abb72e68ab2da897ceecfb8f7d4f0ced0dcf39506b31a46b795c8cee3ee6d789a1f8f7c35eb20eb17c6af5402954ec6eb41576eb2d65078b9755aca0e3af11f438df2a8abfb35d75b3fd151099735908f9b15a42f5211d4ea691014142adae9c9fdf0cf704bc4197d10f8f5f60be29abc805c6fa0f6192e4d12c8f7d50289e0ea796217f453730ca5af1ac3eb3c8ccc4bc161925806506160489a175a07bcf0f9323a4d05013117ba5f3c6d5bc6f6feadcfd093e40efbc19b8648cc8251d6d2faca5da7b506ec4b9e66b821c4176205b9ce0cd4c358b5e2a742c93b9ddb481feca10bb213925e1c661149c04e84a7809e440c190977cf015f12b6259581c368c70eec633985b78c1108f7ff42d1cb03d9ce957f705b871b57c3705ada6d6b386e647a3bacf846da4feb5c508bc4960c2d1f5378700b118fd2ea20db2790aafb7d39043bd2ab6f8902111a45fb181be8e83fa5a4c43e5d2d56797042f8d0c3e832857db0fccc61e7ea3616b70da0439eedf1a1a40196435c99b24e2ab07f8515272972faeafb2670ff66b237b00bf092da2de98a99ed4319498b4d8385aa68e36974b9c31d44b2dfebda78b3465b859296c63958cbcb587dd82e04c51986fdb9e0f3a2941ef1eac8d3b08c2fcd32ceb9dc434096c7f03e529c82132cd7e242a5668520baf00332a2de8a4f52420378350993bd35c573ba4f32e5ad89ddca1b7b3ddb0a21b0faa3674de2bdcb3519b86ed33a8939e6c7cbb9b9493279db28739b163916776bdcc40f7368000b5cefb3425b77dce84a957642319cb95226e30e119a4e455795b24e627b69881dc87084c3c1972fd170c87bcf4cc228beb4083a063e7a44c4fa8490f48457d12e4cf44b84ef41556e53599c5b4a030b4d07ee6594b6830ac0cb7823f908130fd6d2f3f9b5d65012f8e9abeeb74f4042a2a8c05fcb28f968f15f4230dfce034595141c770c200c1fd710e86d9b4d820ee0f015762526cb5a148e18874a385acef6f9efb77d43bc14936e8aa966dd53a1d2403a820f735fd60f5867570fa93ffae3214dc9ac93b2c191115a0045f71923249a10fdd8aa6ca35f6420fa1c80a867d7f54ef54b465f151de0b9a040c31d7373c81565d503cc1332dc6808533171ff2513a7139dad63b1848ba46f09255e81f7edab6208e62d17955aa43e27c74b5ed77b8d3c66ea50c478760e0db5c1b8970a22e74a29bd07bed0ba7e9c7a1866531889fa516ffd66c363d9558b2716d67809d85f16b4e18f456d5ec2343d08ea601da77676246c26432bfcd935c0d80a1e32fc41b380dff041a2629683540d5f2b9d9ef6101114242508c68987a44a0169bf8fbdabf1954bd54d745f1d66b7367848e43e0c94a6d88ccbdfd65333301d34d06d400e643e36c681c7f475b0026967d68e58af2fbf4800ca7aad6a43a3782b1d9452226ef881d50fcbb7b4df0c8c3b15ca80321cbb928fa8dce4048f01fc48121eaa1da0a954a6150c3d2e42add1b4f58910c2db0869a5481d469ef4bdccec3e7c0a21253fd19ce941b16808bf14fca6fec2b1ba7f771580235034e5ca95763721d6add9aa3914f476b37097ce67b000d5d";
    const MLDSA44_SIGNED_DATA_RAW: &str = "a9ac51f0c0f8b81464e2e440ad163fbb500bb8365f6fea3e9e352a611cb13418ddb4d7f8ec628218e9fc1d91313bc47d09cb603aac5c06c5974fa5635b0979c3f13aceeadec1b0c812f5ada327ddaea0048183d6029770af240dbef854072455d985e77d9fef6612961f85d6010404bd17416f9489c155c47bf9b0d91da8a334ba6ded0d91ff6b56643be18f61e996b03bd769f1b3fba78d44551fcdbb045abe02de8a82d8c1d9a7a0069b686f7f2dc8f9a4d07a406ee4225013f30ce11fe6110aba9b000f0711dfad663429dcec2f19b36e158c68053a5f82c4942e07f41a8f69d499fc12317dac9b2e845041455f4501c09879f265df36ce7076b64d89bbec95ae0b8047bfd2113e914f1be12ffd6121109708169d5c35ecead563594f4691fac1331ba30d815599f09e6e9f07e2e821aaea285c47b992414161b1e4b7bfd5a890df6b790fc08597a54b1fb69aeedbb7e96e2d5570b694b55c522a52f5cb48c19058bf9ce0d4038c2188d3a31d287dab50d9cb7e2988c66dc748a58fef6c60b76b26f16082cbcb5ff2b9fa0571ff97784a9b014caec0a052d39255a33166d333926ae5022fcc7652f971d8dd436eb6308f0e66796fe307f999702d5e30d656d8cfaacc6d40a9ea7569c1505c7f69ef7877c32acf72ab3d0ee8e7b521046eda38c3c808f7c22db5d24a65fbe247bb435997e4f6d4979fe323d69bd336e630c8b82d69d8053bc8315b3f04304ffd679dbd781563156e6b04b9c9775e3346dd8948e5cad4354107144b49cff7c53639fbaf1f3d33bbbf54d2443b4a8252fc4eb92d62f09e172c3626ccc0756bcb76259cf527dd1fd5bffa51978b0ff6d7847144e967cda5cc05808b4ed8a6e2773e902d21206e8168dc828ed01975ec571363dd3a48a384b90d8e0166712166d2d1f811113f9d97478d9441fb53dcaf1388b1ad7c7705a6961ba313725982d8685000c9d88ff863f403a3e5e53d463255f299996c79c54bbd19b44d19dd5f03bf237c8e85bf679b9cd7d3bad28ede4f9ac380cb73c2a9dd729ab26ee72b0292643633f915cf1a746eae9987076b08720ec0e480e5933da6e93c75cae1a526fbe77ecf87bd7ca50d44b2ff48738b627d2dd39555bbe86b573bbcb025b5c5a5114fb11170704c0bcf1f602306a3e3db8cf3a6dffa65ff6af40effd93092a6540fb0e9d580d0cc92c17e9345a63dfd385bb2cee276c69e6d2a334e53a62f2bed21eedf0c4e557165a4d6c352c8e8275634686d90a275e5c91f17627d21c51dfb17d348c1126b1860e3d530e0c53e408ef39a2e851a03560cdba4b044324092da3292d16f13c2aa3693ace63e7b5e25f1152e4935d317ff027ae2166aec38bafce06717537ce736552b8e76ecf2ed653b2501213d1daf460a49d01216deddd49ebdb5dcd8a7f4b91df2af295d248cf56c690ba17e4c309ca1b401a2bb7d853d8e37e2d749eb9ee9589180654d00163c68ec4b42db0510369cb51749a2879acc6a0e9c91c85e25885cf121d4fe5a8d3b38c8a4960c3689f086d1174bbc68bcfefadfd8a597391dd9a51373cec245fc5658de294e7ed1be8007930dbf94a5b856f91b72e236054d0eec752da1a6dbde9dce877d93a521dc0fe7d18827fc39552dc31e4fb989dd4785ad26976c15e79f6edf83520574018733af95dfcb56a2dc60fb87db7d24431abb0943720ec847ff292b7214f0ad62fb842a7142e607404b2cc8e1faed707e57d7bba00a17cef83fd9d19dd89695b96a1e1fb5b4862c1aae075ad8e859c8c723d3344c6b9daf2e7153bbb836dc7bb9df05c4d4c0e93f13a8ed6f6cc000ba11e5ee51e845931a2abf2686d13715a986b0570ae746461b406df45876748f3502bf4e0f017496d7cb20b2a37bec99219730e404beb3fbb58ea0d0a83a2672a89eacd297d3fbe545e46746e59533ddaec2b62268ab08bc7c8c50951ab1ba161a54f077c5d7ec76c14dd977fe0dc6290ece1d7fb4468d8ecbbb91af2b3fd46ffa92e08d3d29b51cd55e7bbe0b0654fbaeb0f291eb1d1ec9943e60fd0da622c2db26053f4343cfb704e1b0291b48eb39cc48f1845b6eb35890a18a1906c8684bacea478c7bba39be6d736973200e61317d26732572c237048124405ac8d5562287659f1aa434e166ec8c85daab74e3e748d6d98cf9627687c74fb9cf1e92006e2af25555e6a348f9d431533762a8f4035805e9705573ae4bdd3b1f760161ee926db2bba7a3856b5f214b71a64b58e4c5abf0d44b2e372340e063886efd2c87ffab4d764e76dafca0c8bb3d96c077616a6fa13bb1a0cd22318f3def7dd33a617af71792c84d0b3ae645a46cff53c8b8ae31f58c32c216a861bcf14e277b04fc65832a7d436557f220e8cfc82e2d4ce5e8759c4d4d7c4454a5e587f86da4a1376b594409133632295b89c135e649545cc2fc8093e69efac4ce68fb7e5db72c7a8a89edca687509e1de466931201ffbe2eccb9ca9af56318450929805884b4fe9fc790600e98d0e5c6e67c73056131f7e7c03799e473e3ef14db473fb7c3cc53d3cd9b2dca99a0aacdd415696ab872a608bd074f30d48cd6c2669912185c2ac6b9f05100e7e416fe5b693f9b319ebcca720437e968aae8567da9ff9adf74c8683fffb9cc05d12be98af70a6aa5de6b518add9926329abcab4d1230b015d5df27dd03e5c32bd22dbbcb55baa9a055d4c61d9350433538229db7ac4a6a3c5f06bc8ea9870189fb5f727295c2a21f63c6a19418a200546054554228010759f7c993ef995105e4c7c99c2be3be40e7d3472441817447b7a020674d2d1f7532c7898aa6e8d9800b842890bb06fe1cae8e53969305737aeb61f58d14ff31b97db3993973a40a8234532548d8e6d8f00944b1f8e947919e97192d8379678240b7b2f297a073c3c394b12f258c366b83f5d31e75710e33c576a51d45fbba6a1967415a26006a28603d1dcfad72181b30ee88bc4285e0ae07610bc8aee88f0a2ffc73f357580a42c32ca205488856020b0314fc54b8828cba063fafa611c262aff1904e81814cafd9b5940b0294c66d07b3559d4317519c931185ff43d53a384a4e731a2e0b9a4eb84548009edfd6950857787f48f7e5de3bb0d821b68827b7251f16b428c691ae6268da7272b79f44f315edb02ea74d18baff46d4a63f4ea0c9321877c34edc2eb58c05ee9c571303cbd6094ea868aad9825028da80818835f1f3e13301f0b54156a61f4a7f750392323af22f76d94100698c69fd702c88edd5b956bb2960fd435d075a77341c139fe0194b28e0406a573010a203b5063646f73bbc8d8e3ebf2f60a0d14223036393c4979a0abb9c0ccd8d9dafc080c1f3042596f72a4adafb0c5d6e5e8f01c2126383b656c72808a9093acb3b4c0c9d2d3d4dae8f200000000001023344b";

    #[test]
    #[ignore = "Manual test to verify debug format"]
    fn test_key_debug() {
        let key = SigningKey::make(SignatureAlgorithm::Ed25519);
        println!("{:?}", key);
        let verifying_key = key.to_verifying_key();
        println!("{:?}", verifying_key);

        let key = SigningKey::make(SignatureAlgorithm::MlDsa44);
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
    #[ignore = "Run manually to generate ML-DSA-44 test vectors"]
    fn generate_test_vectors_mldsa44() {
        let signing_key = SigningKey::make(SignatureAlgorithm::MlDsa44);
        let verifying_key = signing_key.to_verifying_key();
        let raw_signature = signing_key.sign_raw(b"Test message");

        println!(
            "const MLDSA44_SIGNING_KEY: &str = \"{}\";",
            hex::encode(signing_key.to_cose().as_ref())
        );
        println!(
            "const MLDSA44_VERIFYING_KEY: &str = \"{}\";",
            hex::encode(verifying_key.to_cose().as_ref())
        );
        println!(
            "const MLDSA44_SIGNED_DATA_RAW: &str = \"{}\";",
            hex::encode(raw_signature.as_slice())
        );
    }

    #[test]
    fn test_mldsa44_test_vectors() {
        let signing_key = SigningKey::from_cose(&CoseKeyBytes::from(
            hex::decode(MLDSA44_SIGNING_KEY).unwrap(),
        ))
        .unwrap();
        let verifying_key = signing_key.to_verifying_key();
        assert_eq!(
            verifying_key.to_cose().as_ref(),
            &hex::decode(MLDSA44_VERIFYING_KEY).unwrap()[..]
        );
        verifying_key
            .verify_raw(
                &hex::decode(MLDSA44_SIGNED_DATA_RAW).unwrap(),
                b"Test message",
            )
            .unwrap();
    }

    #[test]
    fn test_cose_roundtrip_encode_signing_mldsa44() {
        let signing_key = SigningKey::make(SignatureAlgorithm::MlDsa44);
        let cose = signing_key.to_cose();
        let parsed_key = SigningKey::from_cose(&cose).unwrap();

        assert_eq!(signing_key.to_cose(), parsed_key.to_cose());
    }

    #[test]
    fn test_sign_roundtrip_mldsa44() {
        let signing_key = SigningKey::make(SignatureAlgorithm::MlDsa44);
        let signature = signing_key.sign_raw(b"Test message");
        let verifying_key = signing_key.to_verifying_key();
        assert!(
            verifying_key
                .verify_raw(&signature, b"Test message")
                .is_ok()
        );
    }
}
