# Bitwarden SDK Lints

This directory contains custom lints for the Bitwarden SDK, implemented using
[dylint](https://github.com/trailofbits/dylint).

The following lints are currently available:

- `error_enum`: Forbids enum variants from having the `Error` suffix.
- `error_suffix`: Ensures that types deriving `std::error::Error` have the `Error` suffix.
- `uniffi_async_export`: Ensures `#[uniffi::export]` on `async fn`s (free or inside an impl)
  specifies `async_runtime = "tokio"`.
