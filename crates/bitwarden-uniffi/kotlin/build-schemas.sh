#!/usr/bin/env bash
set -euo pipefail

cargo run -p uniffi-bindgen generate \
  ./sdk/src/main/jniLibs/arm64-v8a/libbitwarden_uniffi.so \
  --language kotlin \
  --no-format \
  --out-dir sdk/src/main/java

# Wrap every Kotlin->Rust async entry point in withContext(Dispatchers.IO).
# Workaround for mozilla/uniffi-rs#1901; see wrap-async-bindings.js.
node ./wrap-async-bindings.js sdk/src/main/java
