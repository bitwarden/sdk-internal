//! Compatibility types that bridge legacy formats and their [`safe`](crate::safe) replacements.
//!
//! They read both the legacy and the new format. Writing starts on the legacy format and switches
//! to the new one once every supported client can read it, so stored data migrates as it is
//! re-sealed.

mod legacy_compat_symmetric_key_envelope;
pub use legacy_compat_symmetric_key_envelope::*;
