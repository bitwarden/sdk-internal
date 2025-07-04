//! This module contains the low-level public-key encryption implementations.
//! Any modifications to this module need to be most thoroughly reviewed.
//!
//! This module should only be referenced by the `public_key_encryption` module.
mod rsa;
pub(super) use rsa::encrypt_rsa2048_oaep_sha1;
