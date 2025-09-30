use std::{borrow::Cow, fmt::Display, str::FromStr};

use bitwarden_encoding::{B64, FromStrVisitor};
pub use internal::UnsignedSharedKey;
use rsa::Oaep;
use serde::Deserialize;

use super::{from_b64_vec, split_enc_string};
use crate::{
    AsymmetricCryptoKey, AsymmetricPublicCryptoKey, BitwardenLegacyKeyBytes, RawPrivateKey,
    RawPublicKey, SymmetricCryptoKey,
    error::{CryptoError, EncStringParseError, Result},
    rsa::encrypt_rsa2048_oaep_sha1,
};
// This module is a workaround to avoid deprecated warnings that come from the ZeroizeOnDrop
// macro expansion
#[allow(deprecated)]
mod internal {
    #[cfg(feature = "wasm")]
    #[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
    const TS_CUSTOM_TYPES: &'static str = r#"
    export type UnsignedSharedKey = Tagged<string, "UnsignedSharedKey">;
    "#;

    /// # Encrypted string primitive
    ///
    /// [UnsignedSharedKey] is a Bitwarden specific primitive that represents an
    /// asymmetrically encrypted symmetric key. Since the symmetric key is directly encrypted
    /// with the public key, without any further signature, the receiver cannot guarantee the
    /// senders identity.
    ///
    /// [UnsignedSharedKey] type allows for different encryption algorithms
    /// to be used which is represented by the different variants of the enum.
    ///
    /// ## Note
    ///
    /// For backwards compatibility we will rarely if ever be able to remove support for decrypting
    /// old variants, but we should be opinionated in which variants are used for encrypting.
    ///
    /// ## Variants
    /// - [Rsa2048_OaepSha256_B64](UnsignedSharedKey::Rsa2048_OaepSha256_B64)
    /// - [Rsa2048_OaepSha1_B64](UnsignedSharedKey::Rsa2048_OaepSha1_B64)
    ///
    /// ## Serialization
    ///
    /// [UnsignedSharedKey] implements [std::fmt::Display] and [std::str::FromStr] to allow
    /// for easy serialization and uses a custom scheme to represent the different variants.
    ///
    /// The scheme is one of the following schemes:
    /// - `[type].[data]`
    ///
    /// Where:
    /// - `[type]`: is a digit number representing the variant.
    /// - `[data]`: is the encrypted data.
    #[allow(missing_docs)]
    #[derive(Clone, zeroize::ZeroizeOnDrop)]
    #[allow(unused, non_camel_case_types)]
    pub enum UnsignedSharedKey {
        /// 3
        Rsa2048_OaepSha256_B64 { data: Vec<u8> },
        /// 4
        Rsa2048_OaepSha1_B64 { data: Vec<u8> },
        /// 5
        #[deprecated]
        Rsa2048_OaepSha256_HmacSha256_B64 { data: Vec<u8>, mac: Vec<u8> },
        /// 6
        #[deprecated]
        Rsa2048_OaepSha1_HmacSha256_B64 { data: Vec<u8>, mac: Vec<u8> },
    }
}

/// To avoid printing sensitive information, [UnsignedSharedKey] debug prints to
/// `UnsignedSharedKey`.
impl std::fmt::Debug for UnsignedSharedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnsignedSharedKey").finish()
    }
}

/// Deserializes an [UnsignedSharedKey] from a string.
impl FromStr for UnsignedSharedKey {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (enc_type, parts) = split_enc_string(s);
        match (enc_type, parts.len()) {
            ("3", 1) => {
                let data = from_b64_vec(parts[0])?;
                Ok(UnsignedSharedKey::Rsa2048_OaepSha256_B64 { data })
            }
            ("4", 1) => {
                let data = from_b64_vec(parts[0])?;
                Ok(UnsignedSharedKey::Rsa2048_OaepSha1_B64 { data })
            }
            #[allow(deprecated)]
            ("5", 2) => {
                let data = from_b64_vec(parts[0])?;
                let mac: Vec<u8> = from_b64_vec(parts[1])?;
                Ok(UnsignedSharedKey::Rsa2048_OaepSha256_HmacSha256_B64 { data, mac })
            }
            #[allow(deprecated)]
            ("6", 2) => {
                let data = from_b64_vec(parts[0])?;
                let mac: Vec<u8> = from_b64_vec(parts[1])?;
                Ok(UnsignedSharedKey::Rsa2048_OaepSha1_HmacSha256_B64 { data, mac })
            }

            (enc_type, parts) => Err(EncStringParseError::InvalidTypeAsymm {
                enc_type: enc_type.to_string(),
                parts,
            }
            .into()),
        }
    }
}

impl Display for UnsignedSharedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts: Vec<&[u8]> = match self {
            UnsignedSharedKey::Rsa2048_OaepSha256_B64 { data } => vec![data],
            UnsignedSharedKey::Rsa2048_OaepSha1_B64 { data } => vec![data],
            #[allow(deprecated)]
            UnsignedSharedKey::Rsa2048_OaepSha256_HmacSha256_B64 { data, mac } => {
                vec![data, mac]
            }
            #[allow(deprecated)]
            UnsignedSharedKey::Rsa2048_OaepSha1_HmacSha256_B64 { data, mac } => {
                vec![data, mac]
            }
        };

        let encoded_parts: Vec<String> = parts
            .iter()
            .map(|part| B64::from(*part).to_string())
            .collect();

        write!(f, "{}.{}", self.enc_type(), encoded_parts.join("|"))?;

        Ok(())
    }
}

impl<'de> Deserialize<'de> for UnsignedSharedKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl serde::Serialize for UnsignedSharedKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl UnsignedSharedKey {
    /// Encapsulate a symmetric key, to be shared asymmetrically. Produces a
    /// [UnsignedSharedKey::Rsa2048_OaepSha1_B64] variant. Note, this does not sign the data
    /// and thus does not guarantee sender authenticity.
    pub fn encapsulate_key_unsigned(
        encapsulated_key: &SymmetricCryptoKey,
        encapsulation_key: &AsymmetricPublicCryptoKey,
    ) -> Result<UnsignedSharedKey> {
        match encapsulation_key.inner() {
            RawPublicKey::RsaOaepSha1(rsa_public_key) => {
                Ok(UnsignedSharedKey::Rsa2048_OaepSha1_B64 {
                    data: encrypt_rsa2048_oaep_sha1(
                        rsa_public_key,
                        encapsulated_key.to_encoded().as_ref(),
                    )?,
                })
            }
        }
    }

    /// The numerical representation of the encryption type of the [UnsignedSharedKey].
    const fn enc_type(&self) -> u8 {
        match self {
            UnsignedSharedKey::Rsa2048_OaepSha256_B64 { .. } => 3,
            UnsignedSharedKey::Rsa2048_OaepSha1_B64 { .. } => 4,
            #[allow(deprecated)]
            UnsignedSharedKey::Rsa2048_OaepSha256_HmacSha256_B64 { .. } => 5,
            #[allow(deprecated)]
            UnsignedSharedKey::Rsa2048_OaepSha1_HmacSha256_B64 { .. } => 6,
        }
    }
}

impl UnsignedSharedKey {
    /// Decapsulate a symmetric key, shared asymmetrically.
    /// Note: The shared key does not have a sender signature and sender authenticity is not
    /// guaranteed.
    pub fn decapsulate_key_unsigned(
        &self,
        decapsulation_key: &AsymmetricCryptoKey,
    ) -> Result<SymmetricCryptoKey> {
        match decapsulation_key.inner() {
            RawPrivateKey::RsaOaepSha1(rsa_private_key) => {
                use UnsignedSharedKey::*;
                let key_data = match self {
                    Rsa2048_OaepSha256_B64 { data } => {
                        rsa_private_key.decrypt(Oaep::new::<sha2::Sha256>(), data)
                    }
                    Rsa2048_OaepSha1_B64 { data } => {
                        rsa_private_key.decrypt(Oaep::new::<sha1::Sha1>(), data)
                    }
                    #[allow(deprecated)]
                    Rsa2048_OaepSha256_HmacSha256_B64 { data, .. } => {
                        rsa_private_key.decrypt(Oaep::new::<sha2::Sha256>(), data)
                    }
                    #[allow(deprecated)]
                    Rsa2048_OaepSha1_HmacSha256_B64 { data, .. } => {
                        rsa_private_key.decrypt(Oaep::new::<sha1::Sha1>(), data)
                    }
                }
                .map_err(|_| CryptoError::KeyDecrypt)?;
                SymmetricCryptoKey::try_from(&BitwardenLegacyKeyBytes::from(key_data))
            }
        }
    }
}

/// Usually we wouldn't want to expose UnsignedSharedKeys in the API or the schemas.
/// But during the transition phase we will expose endpoints using the UnsignedSharedKey
/// type.
impl schemars::JsonSchema for UnsignedSharedKey {
    fn schema_name() -> Cow<'static, str> {
        "UnsignedSharedKey".into()
    }

    fn json_schema(generator: &mut schemars::generate::SchemaGenerator) -> schemars::Schema {
        generator.subschema_for::<String>()
    }
}

#[cfg(test)]
mod tests {
    use schemars::schema_for;

    use super::UnsignedSharedKey;
    use crate::{AsymmetricCryptoKey, SymmetricCryptoKey};

    const RSA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCXRVrCX+2hfOQS
8HzYUS2oc/jGVTZpv+/Ryuoh9d8ihYX9dd0cYh2tl6KWdFc88lPUH11Oxqy20Rk2
e5r/RF6T9yM0Me3NPnaKt+hlhLtfoc0h86LnhD56A9FDUfuI0dVnPcrwNv0YJIo9
4LwxtbqBULNvXl6wJ7WAbODrCQy5ZgMVg+iH+gGpwiqsZqHt+KuoHWcN53MSPDfa
F4/YMB99U3TziJMOOJask1TEEnakMPln11PczNDazT17DXIxYrbPfutPdh6sLs6A
QOajdZijfEvepgnOe7cQ7aeatiOJFrjTApKPGxOVRzEMX4XS4xbyhH0QxQeB6l16
l8C0uxIBAgMBAAECggEASaWfeVDA3cVzOPFSpvJm20OTE+R6uGOU+7vh36TX/POq
92qBuwbd0h0oMD32FxsXywd2IxtBDUSiFM9699qufTVuM0Q3tZw6lHDTOVG08+tP
dr8qSbMtw7PGFxN79fHLBxejjO4IrM9lapjWpxEF+11x7r+wM+0xRZQ8sNFYG46a
PfIaty4BGbL0I2DQ2y8I57iBCAy69eht59NLMm27fRWGJIWCuBIjlpfzET1j2HLX
UIh5bTBNzqaN039WH49HczGE3mQKVEJZc/efk3HaVd0a1Sjzyn0QY+N1jtZN3jTR
buDWA1AknkX1LX/0tUhuS3/7C3ejHxjw4Dk1ZLo5/QKBgQDIWvqFn0+IKRSu6Ua2
hDsufIHHUNLelbfLUMmFthxabcUn4zlvIscJO00Tq/ezopSRRvbGiqnxjv/mYxuc
vOUBeZtlus0Q9RTACBtw9TGoNTmQbEunJ2FOSlqbQxkBBAjgGEppRPt30iGj/VjA
hCATq2MYOa/X4dVR51BqQAFIEwKBgQDBSIfTFKC/hDk6FKZlgwvupWYJyU9Rkyfs
tPErZFmzoKhPkQ3YORo2oeAYmVUbS9I2iIYpYpYQJHX8jMuCbCz4ONxTCuSIXYQY
UcUq4PglCKp31xBAE6TN8SvhfME9/MvuDssnQinAHuF0GDAhF646T3LLS1not6Vs
zv7brwSoGwKBgQC88v/8cGfi80ssQZeMnVvq1UTXIeQcQnoY5lGHJl3K8mbS3TnX
E6c9j417Fdz+rj8KWzBzwWXQB5pSPflWcdZO886Xu/mVGmy9RWgLuVFhXwCwsVEP
jNX5ramRb0/vY0yzenUCninBsIxFSbIfrPtLUYCc4hpxr+sr2Mg/y6jpvQKBgBez
MRRs3xkcuXepuI2R+BCXL1/b02IJTUf1F+1eLLGd7YV0H+J3fgNc7gGWK51hOrF9
JBZHBGeOUPlaukmPwiPdtQZpu4QNE3l37VlIpKTF30E6mb+BqR+nht3rUjarnMXg
AoEZ18y6/KIjpSMpqC92Nnk/EBM9EYe6Cf4eA9ApAoGAeqEUg46UTlJySkBKURGp
Is3v1kkf5I0X8DnOhwb+HPxNaiEdmO7ckm8+tPVgppLcG0+tMdLjigFQiDUQk2y3
WjyxP5ZvXu7U96jaJRI8PFMoE06WeVYcdIzrID2HvqH+w0UQJFrLJ/0Mn4stFAEz
XKZBokBGnjFnTnKcs7nv/O8=
-----END PRIVATE KEY-----";

    #[test]
    fn test_enc_string_rsa2048_oaep_sha256_b64() {
        let key_pair = AsymmetricCryptoKey::from_pem(RSA_PRIVATE_KEY).unwrap();
        let enc_str: &str = "3.SUx5gWrgmAKs/S1BoQrqOmx2Hl5fPVBVHokW17Flvm4TpBnJJRkfoitp7Jc4dfazPYjWGlckJz6X+qe+/AWilS1mxtzS0PmDy7tS5xP0GRlB39dstCd5jDw1wPmTbXiLcQ5VTvzpRAfRMEYVveTsEvVTByvEYAGSn4TnCsUDykyhRbD0YcJ4r1KHLs1b3BCBy2M1Gl5nmwckH08CAXaf8VfuBFStAGRKueovqp4euneQla+4G4fXdVvb8qKPnu0iVuALIE6nUNmeOiA3xN3d+akMxbbGxrQ1Ca4TYWjHVdj9C6abngQHkjKNYQwGUXrYo160hP4LIHn/huK6bZe5dQ==";
        let enc_string: UnsignedSharedKey = enc_str.parse().unwrap();

        let test_key = SymmetricCryptoKey::generate_seeded_for_unit_tests("test");
        assert_eq!(enc_string.enc_type(), 3);

        let res = enc_string.decapsulate_key_unsigned(&key_pair).unwrap();
        assert_eq!(res, test_key);
    }

    #[test]
    fn test_enc_string_rsa2048_oaep_sha1_b64() {
        let private_key = AsymmetricCryptoKey::from_pem(RSA_PRIVATE_KEY).unwrap();
        let enc_str: &str = "4.DMD1D5r6BsDDd7C/FE1eZbMCKrmryvAsCKj6+bO54gJNUxisOI7SDcpPLRXf+JdhqY15pT+wimQ5cD9C+6OQ6s71LFQHewXPU29l9Pa1JxGeiKqp37KLYf+1IS6UB2K3ANN35C52ZUHh2TlzIS5RuntxnpCw7APbcfpcnmIdLPJBtuj/xbFd6eBwnI3GSe5qdS6/Ixdd0dgsZcpz3gHJBKmIlSo0YN60SweDq3kTJwox9xSqdCueIDg5U4khc7RhjYx8b33HXaNJj3DwgIH8iLj+lqpDekogr630OhHG3XRpvl4QzYO45bmHb8wAh67Dj70nsZcVg6bAEFHdSFohww==";
        let enc_string: UnsignedSharedKey = enc_str.parse().unwrap();

        let test_key = SymmetricCryptoKey::generate_seeded_for_unit_tests("test");
        assert_eq!(enc_string.enc_type(), 4);

        let res = enc_string.decapsulate_key_unsigned(&private_key).unwrap();
        assert_eq!(res, test_key);
    }

    #[test]
    fn test_enc_string_rsa2048_oaep_sha1_hmac_sha256_b64() {
        let private_key = AsymmetricCryptoKey::from_pem(RSA_PRIVATE_KEY).unwrap();
        let enc_str: &str = "6.DMD1D5r6BsDDd7C/FE1eZbMCKrmryvAsCKj6+bO54gJNUxisOI7SDcpPLRXf+JdhqY15pT+wimQ5cD9C+6OQ6s71LFQHewXPU29l9Pa1JxGeiKqp37KLYf+1IS6UB2K3ANN35C52ZUHh2TlzIS5RuntxnpCw7APbcfpcnmIdLPJBtuj/xbFd6eBwnI3GSe5qdS6/Ixdd0dgsZcpz3gHJBKmIlSo0YN60SweDq3kTJwox9xSqdCueIDg5U4khc7RhjYx8b33HXaNJj3DwgIH8iLj+lqpDekogr630OhHG3XRpvl4QzYO45bmHb8wAh67Dj70nsZcVg6bAEFHdSFohww==|AA==";
        let enc_string: UnsignedSharedKey = enc_str.parse().unwrap();

        let test_key: SymmetricCryptoKey =
            SymmetricCryptoKey::generate_seeded_for_unit_tests("test");
        assert_eq!(enc_string.enc_type(), 6);

        let res = enc_string.decapsulate_key_unsigned(&private_key).unwrap();
        assert_eq!(res.to_base64(), test_key.to_base64());
    }

    #[test]
    fn test_enc_string_serialization() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Test {
            key: UnsignedSharedKey,
        }

        let cipher = "6.ThnNc67nNr7GELyuhGGfsXNP2zJnNqhrIsjntEQ27r2qmn8vwdHbTbfO0cwt6YgSibDN0PjiCZ1O3Wb/IFq+vwvyRwFqF9145wBF8CQCbkhV+M0XvO99kh0daovtt120Nve/5ETI5PbPag9VdalKRQWZypJaqQHm5TAQVf4F5wtLlCLMBkzqTk+wkFe7BPMTGn07T+O3eJbTxXvyMZewQ7icJF0MZVA7VyWX9qElmZ89FCKowbf1BMr5pbcQ+0KdXcSVW3to43VkTp7k7COwsuH3M/i1AuVP5YN8ixjyRpvaeGqX/ap2nCHK2Wj5VxgCGT7XEls6ZknnAp9nB9qVjQ==|s3ntw5H/KKD/qsS0lUghTHl5Sm9j6m7YEdNHf0OeAFQ=";
        let serialized = format!("{{\"key\":\"{cipher}\"}}");

        let t = serde_json::from_str::<Test>(&serialized).unwrap();
        assert_eq!(t.key.enc_type(), 6);
        assert_eq!(t.key.to_string(), cipher);
        assert_eq!(serde_json::to_string(&t).unwrap(), serialized);
    }

    #[test]
    fn test_from_str_invalid() {
        let enc_str = "7.ABC";
        let enc_string: Result<UnsignedSharedKey, _> = enc_str.parse();

        let err = enc_string.unwrap_err();
        assert_eq!(
            err.to_string(),
            "EncString error, Invalid asymmetric type, got type 7 with 1 parts"
        );
    }

    #[test]
    fn test_debug_format() {
        let enc_str: &str = "4.ZheRb3PCfAunyFdQYPfyrFqpuvmln9H9w5nDjt88i5A7ug1XE0LJdQHCIYJl0YOZ1gCOGkhFu/CRY2StiLmT3iRKrrVBbC1+qRMjNNyDvRcFi91LWsmRXhONVSPjywzrJJXglsztDqGkLO93dKXNhuKpcmtBLsvgkphk/aFvxbaOvJ/FHdK/iV0dMGNhc/9tbys8laTdwBlI5xIChpRcrfH+XpSFM88+Bu03uK67N9G6eU1UmET+pISJwJvMuIDMqH+qkT7OOzgL3t6I0H2LDj+CnsumnQmDsvQzDiNfTR0IgjpoE9YH2LvPXVP2wVUkiTwXD9cG/E7XeoiduHyHjw==";
        let enc_string: UnsignedSharedKey = enc_str.parse().unwrap();

        let debug_string = format!("{enc_string:?}");
        assert_eq!(debug_string, "UnsignedSharedKey");
    }

    #[test]
    fn test_json_schema() {
        let schema = schema_for!(UnsignedSharedKey);

        assert_eq!(
            serde_json::to_string(&schema).unwrap(),
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","title":"UnsignedSharedKey","type":"string"}"#
        );
    }
}
