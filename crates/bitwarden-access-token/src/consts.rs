//! Wire-format constants shared between minting and parsing.

/// The only token version this crate accepts.
pub(crate) const TOKEN_VERSION: &str = "0";

/// Key-derivation name, which `derive_shareable_key` turns into the HKDF salt
/// `bitwarden-accesstoken`. Shared by every [`crate::AccessTokenKind`]; the HKDF `info` is what
/// separates them — see [`crate::AccessTokenKind::derive_info`].
pub(crate) const DERIVE_NAME: &str = "accesstoken";
