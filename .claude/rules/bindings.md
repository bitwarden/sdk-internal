---
paths:
  - "crates/bitwarden-uniffi/**"
  - "crates/bitwarden-wasm-internal/**"
---

# Binding crates

These crates are thin bindings only — no business logic. Implement behavior in feature crates and
expose it here.

- `bitwarden-wasm-internal` targets TypeScript/JavaScript. Build with the crate's `./build.sh` (`-r`
  release, `-b` commercial); output lands in `npm/` (OSS, published as `@bitwarden/sdk-internal`)
  and `bitwarden_license/npm/` (commercial, `@bitwarden/commercial-sdk-internal`). Local client
  development uses `npm link` against those directories.
- `bitwarden-uniffi` targets Swift (`swift/`) and Kotlin (`kotlin/`; local Maven publish via
  `kotlin/publish-local.sh`).
