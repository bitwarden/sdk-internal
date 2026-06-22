//! # Hazardous materials
//!
//! Low-level cryptographic primitives. These operate directly on raw key material and are easy to
//! misuse; prefer the higher-level [`safe`](crate::safe) module where possible.

pub(crate) mod symmetric_encryption;
