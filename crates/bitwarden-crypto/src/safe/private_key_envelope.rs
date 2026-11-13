//! Wrapped private key envelope for sealing a private key with a symmetric key.

use std::str::FromStr;

use bitwarden_encoding::{B64, FromStrVisitor};
use coset::{CborSerializable, CoseEncrypt0Builder, HeaderBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    ContentFormat, KeySlotIds, KeyStoreContext, Pkcs8PrivateKeyBytes, PrivateKey,
    cose::{
        ContentNamespace, SafeObjectNamespace,
        symmetric::{CoseAlgorithmPolicy, decrypt_cose0, encrypt_cose0},
    },
    keys::KeyId,
    safe::{
        KeyEncryptionKey, KeyEncryptionKeyError,
        helpers::{debug_fmt, set_safe_namespaces, validate_safe_namespaces},
    },
};

/// Errors that can occur when sealing or unsealing a private key with envelope operations.
#[derive(Debug, Error)]
pub enum PrivateKeyEnvelopeError {
    /// The wrapping key provided is incorrect or the envelope was tampered with
    #[error("Wrong key")]
    WrongKey,
    /// The envelope could not be parsed correctly
    #[error("Parsing error {0}")]
    Parsing(String),
    /// There is no key for the provided key id in the key store
    #[error("Key missing error")]
    KeyMissing,
    /// The key store could not be written to, for example due to being read-only
    #[error("Could not write to key store")]
    KeyStore,
    /// A wrapping or contained key has an unsupported type
    #[error("Wrong key type")]
    WrongKeyType,
    /// The private key envelope namespace is invalid.
    #[error("Invalid namespace")]
    InvalidNamespace,
}

impl From<KeyEncryptionKeyError> for PrivateKeyEnvelopeError {
    fn from(error: KeyEncryptionKeyError) -> Self {
        match error {
            KeyEncryptionKeyError::Missing => PrivateKeyEnvelopeError::KeyMissing,
            KeyEncryptionKeyError::WrongKeyType => PrivateKeyEnvelopeError::WrongKeyType,
        }
    }
}

/// A private key protected by a [`KeyEncryptionKey`]: an XAES-256-GCM or AES-256-CBC-HMAC
/// wrapping key. The private key is sealed as PKCS#8 DER.
///
/// To migrate a key stored as an [`EncString`](crate::EncString), see
/// [`LegacyCompatPrivateKeyEnvelope`](crate::compat::LegacyCompatPrivateKeyEnvelope) and its
/// migration example.
#[derive(Clone)]
pub struct PrivateKeyEnvelope {
    cose_encrypt0: coset::CoseEncrypt0,
}

impl PrivateKeyEnvelope {
    /// Seals a private key with a [`KeyEncryptionKey`] from the key store.
    pub fn seal<Ids: KeySlotIds>(
        key_to_seal: Ids::Private,
        sealing_key: Ids::Symmetric,
        namespace: PrivateKeyEnvelopeNamespace,
        ctx: &KeyStoreContext<Ids>,
    ) -> Result<Self, PrivateKeyEnvelopeError> {
        // Get the keys from the key store.
        let key_to_seal = ctx
            .get_private_key(key_to_seal)
            .map_err(|_| PrivateKeyEnvelopeError::KeyMissing)?;
        let wrapping_key = KeyEncryptionKey::get_cose_key_view(ctx, sealing_key)?;

        let key_bytes = key_to_seal
            .to_der()
            .map_err(|_| PrivateKeyEnvelopeError::WrongKeyType)?;

        let mut protected_header = HeaderBuilder::from(ContentFormat::Pkcs8PrivateKey).build();
        set_safe_namespaces(
            &mut protected_header,
            SafeObjectNamespace::PrivateKeyEnvelope,
            namespace,
        );
        protected_header.key_id = wrapping_key.key_id().as_slice().into();

        let cose_encrypt0 = encrypt_cose0(
            wrapping_key.algorithm(),
            CoseEncrypt0Builder::new(),
            protected_header,
            key_bytes.as_ref(),
            wrapping_key.key_bytes(),
        )
        .map_err(|_| PrivateKeyEnvelopeError::WrongKeyType)?;

        Ok(PrivateKeyEnvelope { cose_encrypt0 })
    }

    /// Unseals a private key with a [`KeyEncryptionKey`] and stores it in the key store context.
    pub fn unseal<Ids: KeySlotIds>(
        &self,
        wrapping_key: Ids::Symmetric,
        namespace: PrivateKeyEnvelopeNamespace,
        ctx: &mut KeyStoreContext<Ids>,
    ) -> Result<Ids::Private, PrivateKeyEnvelopeError> {
        let wrapping_key = KeyEncryptionKey::get_cose_key_view(ctx, wrapping_key)?;

        validate_safe_namespaces(
            &self.cose_encrypt0.protected.header,
            SafeObjectNamespace::PrivateKeyEnvelope,
            namespace,
        )
        .map_err(|_| PrivateKeyEnvelopeError::InvalidNamespace)?;

        // Require the protected algorithm to match the wrapping key's algorithm, so an envelope
        // sealed with one algorithm cannot be opened as another.
        let key_bytes = decrypt_cose0(
            &self.cose_encrypt0,
            CoseAlgorithmPolicy::Exactly(wrapping_key.algorithm()),
            wrapping_key.key_bytes(),
        )
        .map_err(|_| PrivateKeyEnvelopeError::WrongKey)?;

        // Only PKCS#8 DER is a valid encoding for a sealed private key.
        let content_format = ContentFormat::try_from(&self.cose_encrypt0.protected.header)
            .map_err(|_| PrivateKeyEnvelopeError::Parsing("Invalid content format".to_string()))?;
        if content_format != ContentFormat::Pkcs8PrivateKey {
            return Err(PrivateKeyEnvelopeError::WrongKeyType);
        }

        let key = PrivateKey::from_der(&Pkcs8PrivateKeyBytes::from(key_bytes))
            .map_err(|_| PrivateKeyEnvelopeError::WrongKeyType)?;

        Ok(ctx.add_local_private_key(key))
    }

    /// Get the key ID of the key this envelope was sealed with. Always present in a well-formed
    /// envelope.
    pub fn encrypted_by_key_id(&self) -> Result<KeyId, PrivateKeyEnvelopeError> {
        KeyId::try_from(self.cose_encrypt0.protected.header.key_id.as_slice())
            .map_err(|_| PrivateKeyEnvelopeError::Parsing("Invalid sealing key id".to_string()))
    }
}

impl From<&PrivateKeyEnvelope> for Vec<u8> {
    fn from(val: &PrivateKeyEnvelope) -> Self {
        val.cose_encrypt0
            .clone()
            .to_vec()
            .expect("Serialization to cose should not fail")
    }
}

impl TryFrom<&Vec<u8>> for PrivateKeyEnvelope {
    type Error = coset::CoseError;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        let cose_encrypt0 = coset::CoseEncrypt0::from_slice(value)?;
        Ok(PrivateKeyEnvelope { cose_encrypt0 })
    }
}

impl std::fmt::Debug for PrivateKeyEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("PrivateKeyEnvelope");

        if !self.cose_encrypt0.protected.header.key_id.is_empty() {
            s.field(
                "sealing_key_id",
                &self.cose_encrypt0.protected.header.key_id,
            );
        }

        debug_fmt::<PrivateKeyEnvelopeNamespace>(&mut s, &self.cose_encrypt0.protected.header);

        s.finish()
    }
}

impl FromStr for PrivateKeyEnvelope {
    type Err = PrivateKeyEnvelopeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = B64::try_from(s).map_err(|_| {
            PrivateKeyEnvelopeError::Parsing(
                "Invalid PrivateKeyEnvelope Base64 encoding".to_string(),
            )
        })?;
        Self::try_from(&data.into_bytes()).map_err(|_| {
            PrivateKeyEnvelopeError::Parsing("Failed to parse PrivateKeyEnvelope".to_string())
        })
    }
}

impl From<PrivateKeyEnvelope> for String {
    fn from(val: PrivateKeyEnvelope) -> Self {
        let serialized: Vec<u8> = (&val).into();
        B64::from(serialized).to_string()
    }
}

impl<'de> Deserialize<'de> for PrivateKeyEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

impl Serialize for PrivateKeyEnvelope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let serialized: Vec<u8> = self.into();
        serializer.serialize_str(&B64::from(serialized).to_string())
    }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const TS_CUSTOM_TYPES: &'static str = r#"
export type PrivateKeyEnvelope = Tagged<string, "PrivateKeyEnvelope">;
"#;

bitwarden_ffi::impl_wire_string!(PrivateKeyEnvelope, parse = |wire: String| wire.parse());

/// Content namespace for the private key envelope
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum PrivateKeyEnvelopeNamespace {
    /// The user's private key, sealed with the user key
    UserPrivateKey = 1,
    #[cfg(test)]
    /// Example namespace for testing purposes.
    ExampleNamespace = -3,
    #[cfg(test)]
    /// Another example namespace for testing purposes.
    ExampleNamespace2 = -4,
}

impl PrivateKeyEnvelopeNamespace {
    /// Returns the numeric value of the namespace.
    pub fn as_i64(&self) -> i64 {
        *self as i64
    }
}

impl TryFrom<i128> for PrivateKeyEnvelopeNamespace {
    type Error = PrivateKeyEnvelopeError;

    fn try_from(value: i128) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PrivateKeyEnvelopeNamespace::UserPrivateKey),
            #[cfg(test)]
            -3 => Ok(PrivateKeyEnvelopeNamespace::ExampleNamespace),
            #[cfg(test)]
            -4 => Ok(PrivateKeyEnvelopeNamespace::ExampleNamespace2),
            _ => Err(PrivateKeyEnvelopeError::InvalidNamespace),
        }
    }
}

impl TryFrom<i64> for PrivateKeyEnvelopeNamespace {
    type Error = PrivateKeyEnvelopeError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Self::try_from(i128::from(value))
    }
}

impl From<PrivateKeyEnvelopeNamespace> for i128 {
    fn from(value: PrivateKeyEnvelopeNamespace) -> Self {
        value.as_i64().into()
    }
}

impl ContentNamespace for PrivateKeyEnvelopeNamespace {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        KeyStore, PublicKeyEncryptionAlgorithm, SymmetricCryptoKey, SymmetricKeyAlgorithm,
        cose::{AES_256_CBC_HMAC_SHA256_AEAD, XAES_256_GCM},
        traits::tests::{TestIds, TestPrivateKey, TestSymmKey},
    };

    const NAMESPACE: PrivateKeyEnvelopeNamespace = PrivateKeyEnvelopeNamespace::ExampleNamespace;

    const TEST_VECTOR_XAES256_GCM_SEALING_KEY: &str = "pQEEAlAEf6SFm8lC4TUfpOnGdpfXAzoAARF5BIQDBAUGIFggR23gjRd74leOvQDw4SuDsenlg4hv/m2SK3zUsAP8B30B";
    const TEST_VECTOR_XAES256_GCM_KEY_TO_SEAL: &str = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDDMi1eOqFljmc7QU8qKgwQlf4/FcZrST24AGNYPuk/oGSg9JCD/d3F/dzN3XAcxY4Ux8RFm/yNa26iPbIVhsos28olbZ5Ev7WtU1Yc9R5JK3mpBKwJLJbVgjFKMwggeR56dFJ7V9rXlqYPwazvjnrXme19PF3d4hW/c9bNQ3AeNLmWBI/scp0jeFG7IqQBVE3yfeigtr/mOUsMX+uDBoitd/39mkuaefEAArUT7sRgfVy1GsVMq++NphJX+eWfIX9AzMGH9QdWwxffI3WE1VyG9wb7vBUHHls4NsjIcZavDw/HVOWLJoR9yCC3WQ2RuXrVgFgktBAqLjPHbwtO36NfAgMBAAECggEAL8bTVfIR2RKu79D/eHmMNG8SKQzCYTYvFh96MXpMixdOKhtSWAxGQRTu+7CMpW4xZaKzxrn0agT2sl1Zfm1chPhTFTAsgfVOmZsBQ9s3S3+JqrYLCb/RN3dDaz7saU5cCGr6WVhap1QnV0n3czczmBwEBhhFfW6+FftbgyhThADDxqoS6cZtvj3jQPycR3zq9Og5RSOOlkyoyb+jiBJWgvxYsxwlpJEoQMJvlcDqhJt2BD3+MV6Mm8rwyWwYZ3HpOYekfgb/EfDGzLy0DOKCRHa1X5ujSPA+pf+8bIXmt4fhPOmdBKQYH5pxf/OrH51pjLpgdNDQLXmlD/hRCsMiwQKBgQDKVM1FsbDGmG5XFZJPw8ohTn9bEzG4HFHWG+wouCyIP3pj7pyWhq23XdlmndU/wrTU2MWrbsd6mLK9NF3P41NtZYXQVu/tABzzIa9F8AtxUFVaJH8UebUyk8MwxRUuc35+y6S2W60+9uhQBVmlUbZv6RvLh99WB/JPIfdfBlCNoQKBgQD2+NwbO3xgMha9C+16ZaRO7G4KWOOoBTheORNEh1CRimZtHEV+zhNblGzviJaZ5b5GZrKdTNge7orKi2CwGO/ws9QNXVSgI/9Lk4mGzeW/wdfb4hcd8Jqnj66/WSLOkk8S6NfHq65/vAp8+8Yg+N+kiyOf64l2zDOFocpz4fiQ/wKBgDHjLOXVRTACX5prQDMYpFsH/tDW77hkiy0On3D+0EQb2rKPH97hgC2pHzR1ECJzgKDGfh6h5t9sjQ2nvsXGWEit8ouHFAtMrtan5I6K/FdJJnJec1L6G1pIIqWAwpM8eOEMlyU7f4D54hfw6cSgXCpFwMuzSbbtqKooRtUQOoZhAoGBAPZrC8KoMcsRbxqlAgfzzmNpB8qPMmb8/mcU76KamMr+moAXi0egejQP/jlpwUpArv8zjNfiSmlifVzmgEx0NUOnSdcj3kICaMGRrdCxM6GG2cfs6D/ZR5YUiLknSNFvrjIh3Nq+89dDWfumguN3Lj3RDnSL4JaF3IpjCctiFk8lAoGBAIM4c9yXR/1N0C+hfnMxh8kJVf22HdY8BF4XAgig7CDwKdIpoN/vqNlvm2EjVH0Vgp3XqFLzf4v65D89EVHRNEjnwW1gRXc67ttmHuySImoMlkpKXxhOiRMPlMfs0nZNUWUOlNGevnVglKPcRrciNhd+41yhfYT7A5epiQB2RWhx";
    const TEST_VECTOR_XAES256_GCM_ENVELOPE: &str = "g1gppQE6AAEReQMZARwEUAR/pIWbyULhNR+k6cZ2l9c6AAE4gQQ6AAE4gCKhBVgY6D3QYe9jjatccDVtYH9YEGcOJyA3viSyWQTSuNVJpJwpspTNHKWKTCT7DupQF3gMvRSM76tSEu8SV1eSLwfLCptIManfk7sBUhN7JlkzUTyo1V99fWFA0x8xzuex7K5J8NF3iL3fcptKQhjsxYWdi2MwhLgIvsQxq4a5domqsee8ODhVXRmPD/dfmr/ssPk/bIY9S7Qd/yAasc3pXIm0ggTxBws8ELCkDKi3PX18xxgeztW/15TmOQltH5cs4RD8Y9OJUYKjVEWaz3qspB50VfbVUigq2NzfseW0UcLkQeSWpUabvwtjgHyJUYxJTVuiOA83wxtgOcY8s6gmyekI5UgG0Bw4QRzoxunfaoJZsQKm52A3XUGyu+GK+WjifnI2T5MS0PLLfTaPNrxmtWN4go3K2mlxSRz/MwKWJThgtZiZ9J4b6wbAM4wQ2Nhum6dyhoHMKfycn5Ytn3P2uFbDT/j7yA0eVaavAyw+vZ5xmp5s4k79/Le5Ldg3e8i1555JXhGE2cY/rskFsbrtBadhDRTgZwQKr+Od0T+UTPG5JNMu6Jx5byzxIw+4RRrlvuH7/I02QZ+8WUulxG1IpWVf5uyyvdH/Kck7xzlOrsoyZYWM26y0lb1HEl7Lx1XEckES3xdblKjvBA/xMoA+27iuqr2GUz8ZXJAwji125doFiNy9BSF3qIS+x1VfSPY9ZQSdgBQGdBYXx58viCXCQj3d5CoeZjUGyacdKwfAU+M0ob2R+THQu2iHWvOQTx/RPL9/9EnD4qJTrBXLV/F97lyNjve+jTZjtYNYJx0y6TAKkgumU1IrdcN3hqxUVaDTYUWNloQlnFZquHn1WGPZM8wLvYdfDr+vnJxUsTyt6luFM52MQ4YtuZGPqtDOlph88b1LFTm3OyypfGrkbDW2K1e0CSpFereM/RA9r09B8tlIccET1mpBxNQpIXogrRhtnA1ItRXCacaJ60kz2vWcf8Jg5F3rDcCcYIO9WrhkfQRTRUBs4rsyRrINfEtFAfFqjxr3jkrz6ISpHFOafAneihIREgj9Rpu2O4h1AJoq4XVp0oQOie2AhvwE1pG5LR2vIlkDKyoTwV6J5odcfHDR7jxSfG/g4W3mfdU30mwugEtVxfaIlUiaPePNLRm0vhmXGSO1fiFgMC1J2evAi9t7hR7DV0z239zGhXpOVPAwvXAkmU5gnEDSLmD3V1j5yU3vkFBDkOFZ5degdwLYot9Ywj3LUjhllTWMK36BJ2m/mBDH9iV873aXUcrNtO+b0RsYje/IoIlC9Gj30TgrAP5IKWH+Cnj+2EURILKZOhnaSe+G+QJ6ZLE9okNxt/VdUDKPmEnldXf6EOOjcRsMTZ4wwa7o4TUrTG3joA+esG5ekNfUlPjcboN5fG0ytYnmWC9KeEOa5fhD+I7tmLx6abYPLCwRHddse1wzmexnQVERXtkFTCJpq7PkDwYooM1jJtkKuj05acqs11BeWq2FiXnMwVgYSeCK0oiWBpm98rKiMtxj1BgtegL+QhcODJDAGaaYII5N+AuqblDcEALhI2+GCWXca5qp8A6r6vxcYg8rAj/FicrQyDlg6J0IWUisfvTX/+JCWR378eMcKUBrKeZzR09r6onKeA2a9NfCbyTL9pCWqjq+7d40sz1QiZ2Q2JkDaWSXP4tDCXZNFgNxhF+5PA==";

    const TEST_VECTOR_AES256_CBC_HMAC_SEALING_KEY: &str =
        "VExJTUPmcFPNPkB6MQbC5ZGyjxBHb/S8LgcVTgTq0NZ6vRwbm1xa9/o13WNgN2LgEoc1z7z+rT9DO2XMnd0fKA==";
    const TEST_VECTOR_AES256_CBC_HMAC_KEY_TO_SEAL: &str = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDT9iWZDv8Z48OgUtgl67BOzBkxZv1UNivSZwxXIW4kbRuLjeKadO2z3+870O3oRpG0AwPrWybQU9WA1+K7wUpCXVGM3bHXkYdG6zSp6X0bJJ1AaySO+/nHSVjHQKAKDeMv1y3tnBnffXMY0weYc+aZPOGnMtHI18VHMYVwcZfG2sJIGp1zICnOLiXgH3WrKR67PCio5B25Jpe9nGZ3cwlw9uUE9hm66V9qkJ90E2begLQX+D059vunMRw5Vdpe1AGH6SngUNV0ILG7UK/KIZFxup3QKWoMjN5UmoZtAeTZwTCRbYCAGoFrBFrqvLVxHptZkjqzUqlBjqTXBMW9PDhbAgMBAAECggEAFOFSotlPWAWP5+NBV7r4C0sf0DYNDpaninqMRKkOaJg29nBrujt6jxWoQ4Q5a4BIKiuB31WDZVJc3exmcYiBADihJ/dO5aV4ZgwVjAdsQ5g/xXDIkS1RVchr7nT3TwY/Mx9HbvjJs7Jv/CoNvX7tYHsW35mqANcAoBrIwmLuSLBmFB9ZOxd9lLdspQbyX7BTi7TgBP0PDr+ZMRDxVg0altIJwCiyuJ+HY8ncfO9X/nB31HxIGRLnzvqvME6n2fKbS/bxt55hK5G45T9bgK/DKtzp3LtCulpQnSy4X6gTzRY4DWiCpGwMWDNe+Ct62nOr4bQ78noPjAQKnVqavfp5wQKBgQDWEEMuwYKwo645FG3fAlpgPs9DyDJ/089cJdcGXehJiHUPjmLruo/tUjMB7gToJYuvD98COVOjSS0iSvtQ3514pQsA8qeNeuyYRLrHGJi6SJ4K8sqLL4+XzwHZsmxlFeSy3AscJCYZ8iTMgvy1RM/qHVVCoVWpQo0tN6V69AMtZwKBgQD9fHbIsFFQE8c/GPQ6t+1i9yyqwHPqMimOC3kldANE/KBDxSZB7yFL5Y9omE2+ko39if9agzci/7N5VivmGjz9DASizKqEzaEMLj+YHeVRMBZb63FKfzVOeQNb+vZuv1cNlaO8/IWpmoKkeHc8hxePtq6g4nvPOEfyBAroGy1Q7QKBgDtxgqZ+OCODIINbR/NwvNYTOw0wj81tbRzCqUZsV2/sA83RFWkugn89n0p+5T/uBS8U8jG056PlUzI9rjJUFm+FLVwTBjJEm2ThWRimnOrF9ZVGvLYP/AkFBBeG85DSlpKQhklHRIlZ85wTF8filvYFNULueFIrV/bhiANvtV4rAoGBAI4uehInk/Ruo5voy1UERcr1CcDdIieC63wZQ2KWqB7R9LMOql7hWrPPl5j7lOAIJEzKUsjaQNsIwgqVIxp2LS9ixlbqpdrH3EWQy2rvmejoKCJ29ZzrrWLOzeuR4RhNiu67uJQQsIhpek32pCr3O2gI9/qWDww0bWZ6jgOS+uAhAoGBAKD1885KQ+o2NyHt9+BBobalAvpLwBXJz4YFpbkn752iD+8binW3wYbMUpyHjNLGoTK8opvuxHcLDLQdJp8JiJQoYf8MA4GSu78bb4Y0uAv+x3Npyh+vwZ5g2Bh1ld6hyjt7oiVcKRqHiLbENKKw9ktnlqMe7BlIEn17sdfGAhCi";
    const TEST_VECTOR_AES256_CBC_HMAC_ENVELOPE: &str = "g1gppQE6AAERegMZARwEUG8nJKeDe4O4g86qOeZIuDE6AAE4gQQ6AAE4gCKhBVBWT5pQ8Wc8Bc2+An7wFNOeWQTwfR7ZCdGcRJByvUxkW+YfatBFObmn7L7DIwJloja2egqekHAhukDm/ln5dxssCXvX7Zlpm6GCTK8jSmowS6piejovSL/c3PYAgiI7+j8uyMndozw8hzgPlAPTZQGBJuztouRzkGTb+CbmvNq2hq7Lg5sTtkt5NH/ahybPR6zK3c/xxKkPuy+YTfepKeY3SnaHiR3SKXQY1hCJ2LjLGaNf15rkX6HdTH+OH+B5y/avCfcUn1Y+WZ39aUbPIwt+2fvsPOPfsXAX3Sb+POWf/EOmQBv9LnXbqMAXBsq2RVtlbXozEDPC1aL9yHvZFRR+gYzxMMzT2yMa8CLtxMhjAawnlwrtUG2WIq2qL+Sib5fnzyiy7eC39f/hC/f/H81fcF0NA/KpSnBG8uUnjhc9plPIqZ+3bDzaMW6ww0VBDCKITjPWduRiwIty2mYNf6q2AoDgRW2pqXVVEsYbulFxULqSnGW16/w8mBEq8QTv9gnXTtqajfHzZz1tM93J8Df56PKcoQTSrNvlAv3qfE7tz3MH10qsUMljYbfyICz0EjLzsWcD5EzLX9xXNLEWX+5HsSHBpEn/xyStJZj4jaWMWkQpouuLDJvP23t36tdwWAuc1eBwjanEP/pSc7B37u3flaPxvr59bZYuLv8DDxRBDQhY0ir5OfamwNTjQnvgdys8vdmgLKEffXwRjidgdCulydjIh7Twe0j4KlMTsGlYBZliVOs1UBqTJ0QXG4DLZ1ZozpP24vggOFwvGqPWd+yIrwMTv7jTCLniCLy3IVUxnqBx2QCPDHjDg3D74KTU+4701isb8XzHSLnI3vs/G1v3wnOAWG5XmYvZ9lAanfIhhIS7O+uQSc0jIBzsxLT9pexq+96NwivV+XLW+UnmcyWYhRgtS1OHOlEo9yonD0+cNO5Ns+GKVsdWJRsN5Rs6cmGhOk9bHLIVkC0aA41q2Ka09eEapCCd1GrL/rtAnZqO6XOGImf70wmdseb3Bpct3FsysT3MwjgYlQ0NojtRnXaqjD99e7YNV6Rvv6DhevCzbLAbapaTCGKZmYo+qYzPFcN8mM1nb/XvTzck8I+nvyaeE1n6xbT4mkBcDXV5FNQUhRgpZw9GnwtYC8Ydk88ncTu1m4IXHEXbC+fRTLHSDErrD+kWVkihLqAhXJ6xN0rsktBw9lvQapc8WwlMiwOhQySbNu26qr34QQdy2l0deNs4g6HpaCTQqUjU2RdamWbeTpeF6f9Z1kZ9EtOrsuGVRJzgl4ClLsUZCkhCETIiETxO5zOEPYTMgjUau6LrOpcfUBgAFjXvGsbSFWTxTcoojwLvIhirGU0PpfF1vqqGZuS3M7kE65NzTkN0e+fbaLpFs2pIbbTjtlu8h8i9a/EjC4irU/uAgGHjWxtz7Gqe5nPaYsFcjjvY9AbVxiQ4C7JPM9GVa9xv6pi9WBq9f1PusKiqbdRnl6lJAdxEGXIrbmJ2CkBHU+dwCJcA2v8gpvvt0HlvBPqMP5FvqyQFDs76aN88Z2KthHnVoeg6MgLynmmkmwjYPY/jfXTsihU3D6ERJAeP6hqHPS/sF1ID3jQTIPqg099X0xpystxl/F2V77xoIrdYw96vaycl09/MpQ3wnG1uQrE9PK/oyoa8BzddP/GSKclvTyKjfj/BmMxgnkvLtbZuC4c50g2b08JaRAE1DwgCYA==";

    /// An envelope pinned as a test vector, the keys it was sealed from, and how to generate it.
    struct TestVector {
        /// Used in the generated constant names and in assertion messages.
        name: &'static str,
        sealing_key_algorithm: SymmetricKeyAlgorithm,
        cose_algorithm: coset::Algorithm,
        sealing_key: &'static str,
        /// Base64 PKCS#8 DER.
        key_to_seal: &'static str,
        envelope: &'static str,
    }

    /// One vector per supported wrapping key algorithm, each sealing an RSA-2048 private key.
    const TEST_VECTORS: [TestVector; 2] = [
        TestVector {
            name: "XAES256_GCM",
            sealing_key_algorithm: SymmetricKeyAlgorithm::XAes256Gcm,
            cose_algorithm: coset::Algorithm::PrivateUse(XAES_256_GCM),
            sealing_key: TEST_VECTOR_XAES256_GCM_SEALING_KEY,
            key_to_seal: TEST_VECTOR_XAES256_GCM_KEY_TO_SEAL,
            envelope: TEST_VECTOR_XAES256_GCM_ENVELOPE,
        },
        TestVector {
            name: "AES256_CBC_HMAC",
            sealing_key_algorithm: SymmetricKeyAlgorithm::Aes256CbcHmac,
            cose_algorithm: coset::Algorithm::PrivateUse(AES_256_CBC_HMAC_SHA256_AEAD),
            sealing_key: TEST_VECTOR_AES256_CBC_HMAC_SEALING_KEY,
            key_to_seal: TEST_VECTOR_AES256_CBC_HMAC_KEY_TO_SEAL,
            envelope: TEST_VECTOR_AES256_CBC_HMAC_ENVELOPE,
        },
    ];

    /// The supported wrapping key algorithms.
    const WRAPPING_KEY_ALGORITHMS: [SymmetricKeyAlgorithm; 2] = [
        SymmetricKeyAlgorithm::XAes256Gcm,
        SymmetricKeyAlgorithm::Aes256CbcHmac,
    ];

    fn to_der(ctx: &KeyStoreContext<TestIds>, key: TestPrivateKey) -> Pkcs8PrivateKeyBytes {
        ctx.get_private_key(key).unwrap().to_der().unwrap()
    }

    fn make_rsa_key(ctx: &mut KeyStoreContext<TestIds>) -> TestPrivateKey {
        ctx.make_private_key(PublicKeyEncryptionAlgorithm::RsaOaepSha1)
    }

    #[test]
    #[ignore = "Manual test to verify debug format"]
    fn test_debug() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let key_to_seal = make_rsa_key(&mut ctx);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

        let envelope = PrivateKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx);
        println!("{:?}", envelope);
    }

    #[test]
    fn test_seal_unseal() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let key_to_seal = make_rsa_key(&mut ctx);

        for wrapping_key_algorithm in WRAPPING_KEY_ALGORITHMS {
            let wrapping_key = ctx.make_symmetric_key(wrapping_key_algorithm);

            let envelope =
                PrivateKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx).unwrap();
            let unsealed_key = envelope.unseal(wrapping_key, NAMESPACE, &mut ctx).unwrap();

            assert_eq!(
                to_der(&ctx, unsealed_key),
                to_der(&ctx, key_to_seal),
                "{wrapping_key_algorithm:?}"
            );
        }
    }

    #[test]
    fn test_encrypted_by_key_id() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let key_to_seal = make_rsa_key(&mut ctx);

        for wrapping_key_algorithm in WRAPPING_KEY_ALGORITHMS {
            let wrapping_key = ctx.make_symmetric_key(wrapping_key_algorithm);

            let envelope =
                PrivateKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx).unwrap();

            // An AES-256-CBC-HMAC key doesn't store a key ID, so `seal` has to write the ID derived
            // from the key material.
            let wrapping_key_id = ctx
                .get_symmetric_key(wrapping_key)
                .unwrap()
                .key_id()
                .expect("Wrapping keys have a key ID");
            assert_eq!(
                envelope.encrypted_by_key_id().unwrap(),
                wrapping_key_id,
                "{wrapping_key_algorithm:?}"
            );
        }
    }

    #[test]
    fn test_string_serialization() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let key_to_seal = make_rsa_key(&mut ctx);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

        let envelope =
            PrivateKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx).unwrap();

        let serialized: String = envelope.into();
        let deserialized = PrivateKeyEnvelope::from_str(&serialized).unwrap();
        let unsealed_key = deserialized
            .unseal(wrapping_key, NAMESPACE, &mut ctx)
            .unwrap();

        assert_eq!(to_der(&ctx, unsealed_key), to_der(&ctx, key_to_seal));
    }

    #[test]
    fn test_wrong_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let key_to_seal = make_rsa_key(&mut ctx);

        for wrapping_key_algorithm in WRAPPING_KEY_ALGORITHMS {
            let wrapping_key = ctx.make_symmetric_key(wrapping_key_algorithm);
            let wrong_key = ctx.make_symmetric_key(wrapping_key_algorithm);

            let envelope =
                PrivateKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx).unwrap();

            assert!(
                matches!(
                    envelope.unseal(wrong_key, NAMESPACE, &mut ctx),
                    Err(PrivateKeyEnvelopeError::WrongKey)
                ),
                "{wrapping_key_algorithm:?}"
            );
        }
    }

    #[test]
    fn test_rejects_unsupported_wrapping_keys() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let key_to_seal = make_rsa_key(&mut ctx);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let envelope =
            PrivateKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx).unwrap();

        let unsupported_wrapping_keys = [
            ctx.make_symmetric_key(SymmetricKeyAlgorithm::Aes256Gcm),
            ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305),
        ];

        for unsupported_wrapping_key in unsupported_wrapping_keys {
            assert!(matches!(
                PrivateKeyEnvelope::seal(key_to_seal, unsupported_wrapping_key, NAMESPACE, &ctx),
                Err(PrivateKeyEnvelopeError::WrongKeyType)
            ));
            assert!(matches!(
                envelope.unseal(unsupported_wrapping_key, NAMESPACE, &mut ctx),
                Err(PrivateKeyEnvelopeError::WrongKeyType)
            ));
        }
    }

    #[test]
    fn test_wrong_namespace() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let key_to_seal = make_rsa_key(&mut ctx);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

        let envelope =
            PrivateKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx).unwrap();

        assert!(matches!(
            envelope.unseal(
                wrapping_key,
                PrivateKeyEnvelopeNamespace::ExampleNamespace2,
                &mut ctx
            ),
            Err(PrivateKeyEnvelopeError::InvalidNamespace)
        ));
    }

    #[test]
    fn test_rejects_symmetric_key_envelope() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let key_to_seal = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XChaCha20Poly1305);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

        // A symmetric key envelope carries the symmetric key envelope object namespace, so it must
        // not open as a private key envelope.
        let symmetric_envelope = crate::safe::SymmetricKeyEnvelope::seal(
            key_to_seal,
            wrapping_key,
            crate::safe::SymmetricKeyEnvelopeNamespace::ExampleNamespace,
            &ctx,
        )
        .unwrap();
        let serialized: String = symmetric_envelope.into();
        let envelope = PrivateKeyEnvelope::from_str(&serialized).unwrap();

        assert!(matches!(
            envelope.unseal(wrapping_key, NAMESPACE, &mut ctx),
            Err(PrivateKeyEnvelopeError::InvalidNamespace)
        ));
    }

    #[test]
    fn test_seal_missing_keys() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let key_to_seal = make_rsa_key(&mut ctx);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);

        assert!(matches!(
            PrivateKeyEnvelope::seal(key_to_seal, TestSymmKey::A(0), NAMESPACE, &ctx),
            Err(PrivateKeyEnvelopeError::KeyMissing)
        ));
        assert!(matches!(
            PrivateKeyEnvelope::seal(TestPrivateKey::A(0), wrapping_key, NAMESPACE, &ctx),
            Err(PrivateKeyEnvelopeError::KeyMissing)
        ));
    }

    #[test]
    fn test_unseal_missing_wrapping_key() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();
        let key_to_seal = make_rsa_key(&mut ctx);
        let wrapping_key = ctx.make_symmetric_key(SymmetricKeyAlgorithm::XAes256Gcm);
        let envelope =
            PrivateKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx).unwrap();

        assert!(matches!(
            envelope.unseal(TestSymmKey::A(0), NAMESPACE, &mut ctx),
            Err(PrivateKeyEnvelopeError::KeyMissing)
        ));
    }

    #[test]
    #[ignore = "Generates test vectors; run manually"]
    fn generate_test_vectors() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        for vector in TEST_VECTORS {
            let key_to_seal = make_rsa_key(&mut ctx);
            let wrapping_key = ctx.make_symmetric_key(vector.sealing_key_algorithm);

            let envelope =
                PrivateKeyEnvelope::seal(key_to_seal, wrapping_key, NAMESPACE, &ctx).unwrap();

            let sealing_key = ctx.get_symmetric_key(wrapping_key).unwrap().to_encoded();
            println!(
                "const TEST_VECTOR_{}_SEALING_KEY: &str = \"{}\";",
                vector.name,
                B64::from(sealing_key.to_vec().as_slice())
            );
            println!(
                "const TEST_VECTOR_{}_KEY_TO_SEAL: &str = \"{}\";",
                vector.name,
                B64::from(to_der(&ctx, key_to_seal).as_ref())
            );
            let serialized: String = envelope.into();
            println!(
                "const TEST_VECTOR_{}_ENVELOPE: &str = \"{serialized}\";",
                vector.name
            );
        }
    }

    #[test]
    fn decrypt_test_vectors() {
        let key_store = KeyStore::<TestIds>::default();
        let mut ctx = key_store.context_mut();

        for vector in TEST_VECTORS {
            let sealing_key = ctx.add_local_symmetric_key(
                SymmetricCryptoKey::try_from(vector.sealing_key.to_string())
                    .expect("Failed to parse sealing key from test vector"),
            );
            assert_eq!(
                ctx.get_symmetric_key_algorithm(sealing_key).unwrap(),
                vector.sealing_key_algorithm,
                "{}",
                vector.name
            );
            let expected_der = B64::try_from(vector.key_to_seal)
                .expect("Failed to parse key to seal from test vector")
                .into_bytes();

            let envelope = PrivateKeyEnvelope::from_str(vector.envelope).unwrap();

            // Pin the header fields that consumers rely on: the algorithm and the ID used to look
            // up the sealing key.
            let header = &envelope.cose_encrypt0.protected.header;
            assert_eq!(
                header.alg.as_ref(),
                Some(&vector.cose_algorithm),
                "{}",
                vector.name
            );
            assert_eq!(
                header.key_id,
                ctx.get_symmetric_key(sealing_key)
                    .unwrap()
                    .key_id()
                    .expect("Sealing keys have a key ID")
                    .as_slice(),
                "{}",
                vector.name
            );

            let unsealed_key = envelope.unseal(sealing_key, NAMESPACE, &mut ctx).unwrap();
            assert_eq!(
                to_der(&ctx, unsealed_key).as_ref(),
                expected_der.as_slice(),
                "{}",
                vector.name
            );
        }
    }
}
