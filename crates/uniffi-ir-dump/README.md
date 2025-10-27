# uniffi-ir-dump

Small helper to dump UniFFI IR JSON from a compiled library for CI diffing.

Usage:

```
# Build the crate
cargo build -p uniffi-ir-dump

# Build the library you want to inspect for a specific target first
cargo build -p bitwarden-uniffi --target aarch64-apple-ios-sim --release

# Dump the IR JSON
./target/debug/uniffi-ir-dump \
  target/aarch64-apple-ios-sim/release/libbitwarden_uniffi.dylib \
  crates/bitwarden-uniffi/swift/tmp/bindings/bitwarden_uniffi.ios-sim.ir.json
```
