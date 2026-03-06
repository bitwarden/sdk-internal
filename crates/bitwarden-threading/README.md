---
category: core
---

# bitwarden-threading

Provides abstractions around threading and async quirks in FFI contexts. Allows a single
implementation to work across native and WASM targets.

## WASM Testing

To run the WASM tests, you can use the following command:

```bash
cargo test --target wasm32-unknown-unknown --all-features -- --nocapture
```
