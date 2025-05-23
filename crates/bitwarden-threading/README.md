# bitwarden-threading

Utility crate for Bitwarden SDK to handle threading and async quirks in FFI contexts.

## WASM Testing

To run the WASM tests, you can use the following command:

```bash
cargo test --target wasm32-unknown-unknown --all-features -- --nocapture
```
