//! The wasm module holds the wasm bindings for [`InviteSecret`], which crosses the WASM boundary as
//! its base64url string form. Encoding/decoding is limited to the `From<&InviteSecret> for String`
//! and `FromStr` implementations to simplify maintenance.
use crate::invite::InviteSecret;

bitwarden_ffi::impl_wire_string!(
    InviteSecret,
    parse = |wire: String| wire.parse(),
    format = |secret: InviteSecret| String::from(&secret),
);
