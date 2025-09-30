#![doc = include_str!("../README.md")]

//! # Pinned heap data
//!
//! This crate uses a `Pin<Box<>>` strategy to ensure data is stored on the heap and not moved
//! around. This pattern is commonly used for `GenericArray` since it's equivalent to `[u8; N]`
//! which is a Copy type placed on the stack. To keep the compiler from making stack copies when
//! moving this struct around, we use a Box to keep the values on the heap. We also pin the box to
//! make sure that the contents can't be pulled out of the box and moved.

#[cfg(not(feature = "no-memory-hardening"))]
#[global_allocator]
static ALLOC: ZeroizingAllocator<std::alloc::System> = ZeroizingAllocator(std::alloc::System);

mod aes;
mod content_format;
pub use content_format::*;
mod enc_string;
pub use enc_string::{EncString, UnsignedSharedKey};
mod error;
pub(crate) use error::Result;
pub use error::{CryptoError, EncodingError};
mod fingerprint;
pub use fingerprint::fingerprint;
mod keys;
pub use keys::*;
mod rsa;
pub use crate::rsa::RsaKeyPair;
mod util;
pub use util::{generate_random_alphanumeric, generate_random_bytes, pbkdf2};
mod wordlist;
pub use wordlist::EFF_LONG_WORD_LIST;
mod store;
pub use store::{
    KeyStore, KeyStoreContext, RotatedUserKeys, dangerous_get_v2_rotated_account_keys,
};
mod cose;
pub use cose::CoseSerializable;
pub mod safe;
mod signing;
pub use signing::*;
mod traits;
mod xchacha20;
pub use traits::{
    CompositeEncryptable, Decryptable, IdentifyKey, KeyId, KeyIds, PrimitiveEncryptable,
};
pub use zeroizing_alloc::ZeroAlloc as ZeroizingAllocator;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

#[cfg(feature = "uniffi")]
mod uniffi_support;
