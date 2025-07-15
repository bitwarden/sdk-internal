//! This module contains the low-level symmetric encryption implementations.
//! Any modifications to this module need to be most thoroughly reviewed.
//!
//! This module should only be referenced by the `symmetric_encryption` module.
pub(super) mod aes;
pub(super) mod xchacha20;
