/**
 * This file contains private-use constants for COSE encoded key types and algorithms.
 */
use coset::iana;

pub(crate) const XCHACHA20_POLY1305: i64 = -70000;

pub(crate) const SYMMETRIC_KEY: i64 = iana::SymmetricKeyParameter::K as i64;