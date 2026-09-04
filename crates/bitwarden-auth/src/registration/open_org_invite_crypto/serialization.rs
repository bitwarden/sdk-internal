//! Wire encoding for [`SealedOpenOrgInviteData`]. Its two internal envelopes are packed with
//! CBOR (compact binary format) then base64url-wrapped so it crosses every boundary as one
//! opaque string — via serde on the Rust side and the WASM ABI (wasm-bindgen's Rust↔JS
//! conversion layer) into TypeScript.

use std::str::FromStr;

use bitwarden_crypto::safe::{DataEnvelope, SecretProtectedKeyEnvelope};
use bitwarden_encoding::{B64Url, FromStrVisitor};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::SealedOpenOrgInviteData;

/// Intermediate shape used to (de)serialize [`SealedOpenOrgInviteData`] to and from its wire
/// bytes. Each envelope is carried as raw bytes under a short field name for compactness.
#[derive(Serialize, Deserialize)]
struct SealedOpenOrgInviteDataWire {
    // Without serde_bytes, Vec<u8> encodes as a CBOR array of integers (~2x the size).
    /// Bytes of the data envelope (OpenOrgInvite plaintext encrypted under a fresh CEK).
    #[serde(rename = "d", with = "serde_bytes")]
    data_envelope: Vec<u8>,
    /// Bytes of the key envelope (the CEK encrypted under the caller's HighEntropySecret).
    #[serde(rename = "k", with = "serde_bytes")]
    key_envelope: Vec<u8>,
}

/// Errors returned when parsing a [`SealedOpenOrgInviteData`] from its wire form.
#[derive(Debug, Error)]
pub enum SealedOpenOrgInviteDataError {
    /// The wire string could not be decoded.
    #[error("Sealed open org invite data is malformed")]
    Malformed,
}

impl FromStr for SealedOpenOrgInviteData {
    type Err = SealedOpenOrgInviteDataError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let outer = B64Url::try_from(s).map_err(|_| SealedOpenOrgInviteDataError::Malformed)?;
        let wire: SealedOpenOrgInviteDataWire = ciborium::de::from_reader(outer.as_bytes())
            .map_err(|_| SealedOpenOrgInviteDataError::Malformed)?;
        let data_envelope = DataEnvelope::from(wire.data_envelope);
        let key_envelope = SecretProtectedKeyEnvelope::try_from(&wire.key_envelope)
            .map_err(|_| SealedOpenOrgInviteDataError::Malformed)?;
        Ok(SealedOpenOrgInviteData {
            data_envelope,
            key_envelope,
        })
    }
}

impl From<&SealedOpenOrgInviteData> for String {
    fn from(val: &SealedOpenOrgInviteData) -> Self {
        let data_bytes: Vec<u8> = (&val.data_envelope).into();
        let key_bytes: Vec<u8> = (&val.key_envelope).into();
        let wire = SealedOpenOrgInviteDataWire {
            data_envelope: data_bytes,
            key_envelope: key_bytes,
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&wire, &mut buf)
            .expect("CBOR encoding of two byte fields cannot fail");
        B64Url::from(buf).to_string()
    }
}

impl From<SealedOpenOrgInviteData> for String {
    fn from(val: SealedOpenOrgInviteData) -> Self {
        (&val).into()
    }
}

impl Serialize for SealedOpenOrgInviteData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&String::from(self))
    }
}

impl<'de> Deserialize<'de> for SealedOpenOrgInviteData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(FromStrVisitor::new())
    }
}

#[cfg(feature = "wasm")]
bitwarden_ffi::impl_wire_object!(SealedOpenOrgInviteData);

#[cfg(feature = "wasm")]
impl wasm_bindgen::describe::WasmDescribe for SealedOpenOrgInviteData {
    fn describe() {
        <String as wasm_bindgen::describe::WasmDescribe>::describe();
    }
}

#[cfg(feature = "wasm")]
impl wasm_bindgen::convert::FromWasmAbi for SealedOpenOrgInviteData {
    type Abi = <String as wasm_bindgen::convert::FromWasmAbi>::Abi;

    unsafe fn from_abi(abi: Self::Abi) -> Self {
        use wasm_bindgen::UnwrapThrowExt;
        let string = unsafe { String::from_abi(abi) };
        SealedOpenOrgInviteData::from_str(&string).unwrap_throw()
    }
}

#[cfg(feature = "wasm")]
impl wasm_bindgen::convert::OptionFromWasmAbi for SealedOpenOrgInviteData {
    fn is_none(abi: &Self::Abi) -> bool {
        <String as wasm_bindgen::convert::OptionFromWasmAbi>::is_none(abi)
    }
}

#[cfg(feature = "wasm")]
impl wasm_bindgen::convert::IntoWasmAbi for SealedOpenOrgInviteData {
    type Abi = <String as wasm_bindgen::convert::IntoWasmAbi>::Abi;

    fn into_abi(self) -> Self::Abi {
        String::from(self).into_abi()
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_encoding::B64Url;

    use super::*;
    use crate::registration::open_org_invite_crypto::{OpenOrgInvite, SealedOpenOrgInviteData};

    fn sample_input() -> OpenOrgInvite {
        OpenOrgInvite {
            organization_id: "1bc9ac1e-f5aa-45f2-94bf-b181009709b8".to_string(),
            invite_link_code: "abcd1234efgh5678".to_string(),
            invite_secret: "raw-invite-secret-material-base64url".to_string(),
        }
    }

    #[test]
    fn sealed_data_wire_is_valid_base64url() {
        let (sealed_data, _) =
            SealedOpenOrgInviteData::seal(sample_input()).expect("seal should succeed");

        let wire = String::from(&sealed_data);
        let decoded =
            B64Url::try_from(wire.as_str()).expect("sealed_data wire must be valid base64url");
        assert_eq!(B64Url::from(decoded.as_bytes()).to_string(), wire);
    }

    #[test]
    fn parse_rejects_truncated_wire() {
        let (sealed_data, _) =
            SealedOpenOrgInviteData::seal(sample_input()).expect("seal should succeed");

        let mut wire = String::from(&sealed_data);
        wire.truncate(wire.len() / 2);

        let err = wire
            .parse::<SealedOpenOrgInviteData>()
            .expect_err("truncated wire must be rejected at parse time");
        assert!(matches!(err, SealedOpenOrgInviteDataError::Malformed));
    }

    #[test]
    fn parse_rejects_malformed_base64url() {
        let err = "not-valid-base64url!"
            .parse::<SealedOpenOrgInviteData>()
            .expect_err("malformed base64url must be rejected at parse time");
        assert!(matches!(err, SealedOpenOrgInviteDataError::Malformed));

        assert!(B64Url::try_from("not-valid-base64url!").is_err());
    }

    #[test]
    fn parse_rejects_valid_cbor_with_bad_key_envelope_bytes() {
        // Well-formed base64url + CBOR wire whose `k` field bytes don't parse as a
        // SecretProtectedKeyEnvelope — exercises the parse-envelope failure path.
        #[derive(serde::Serialize)]
        struct FakeWire<'a> {
            #[serde(rename = "d", with = "serde_bytes")]
            d: &'a [u8],
            #[serde(rename = "k", with = "serde_bytes")]
            k: &'a [u8],
        }
        let fake = FakeWire {
            d: &[1, 2, 3, 4],       // DataEnvelope::from is an infallible byte-wrap; that's fine
            k: &[0xff, 0xff, 0xff], // won't parse as SecretProtectedKeyEnvelope
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&fake, &mut buf).unwrap();
        let wire = B64Url::from(buf).to_string();

        let err = wire
            .parse::<SealedOpenOrgInviteData>()
            .expect_err("bad key-envelope bytes must be rejected at parse time");
        assert!(matches!(err, SealedOpenOrgInviteDataError::Malformed));
    }
}
