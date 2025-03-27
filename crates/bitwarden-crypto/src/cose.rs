/**
 * This file contains private-use constants for COSE encoded key types and algorithms.
 */
use coset::iana;

use serde::{Deserialize, Serialize};
#[cfg(feature = "wasm")]
use tsify_next::Tsify;

pub(crate) const XCHACHA20_POLY1305: i64 = -70000;

pub(crate) const SYMMETRIC_KEY: i64 = iana::SymmetricKeyParameter::K as i64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub enum ContentFormat {
    Utf8,
    Pkcs8,
    CoseKey,
    OctetStream,
    Unknown,
    // This should never be serialized. It is used to indicate when we call an encrypt operation on a complex object that consists of multiple, individually encrypted fields
    DomainObject
}