# Bitwarden SDK Lints

This directory contains custom lints for the Bitwarden SDK, implemented using
[dylint](https://github.com/trailofbits/dylint).

The following lints are currently available:

- `error_enum`: Forbids enum variants from having the `Error` suffix.
- `error_suffix`: Ensures that types deriving `std::error::Error` have the `Error` suffix.
- `repr_with_tsify`: Forbids deriving both `serde_repr` (`Serialize_repr`/`Deserialize_repr`) and
  `tsify::Tsify` on the same type, because the integer wire format produced by `serde_repr`
  disagrees with the string-based TypeScript declaration produced by `Tsify`. Use
  `#[cfg_attr(feature = "wasm", wasm_bindgen)]` for repr-encoded enums.
- `uniffi_async_export`: Ensures `#[uniffi::export]` on `async fn`s (free or inside an impl)
  specifies `async_runtime = "tokio"`.
