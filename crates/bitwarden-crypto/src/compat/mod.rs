//! Compatibility types that bridge legacy formats and their [`safe`](crate::safe) replacements.
//!
//! They read both the legacy and the new format, but only ever write the new one, so stored data
//! migrates as it is re-sealed.

mod legacy_compat_symmetric_key_envelope;
pub use legacy_compat_symmetric_key_envelope::*;
