//! This file contains private-use constants for COSE encoded key types and algorithms.
//! Standardized values from https://www.iana.org/assignments/cose/cose.xhtml should always be preferred
//! unless there is a specific reason to use a private-use value.

// XChaCha20 (https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03) is used over ChaCha20
// to be able to randomly generate nonces, and to not have to worry about key wearout. Since
// the draft was never published as an RFC, we use a private-use value for the algorithm.
pub(crate) const XCHACHA20_POLY1305: i64 = -70000;
