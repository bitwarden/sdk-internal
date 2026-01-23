---
category: bindings
---

# bitwarden-wasm-internal

WebAssembly bindings for the Bitwarden SDK, consumed by the internal Bitwarden web clients. Thin
bindings only - no business logic.

**Note:** This is only for internal use. Bitwarden will not provide any support for this crate.

This crate should contain no logic but rather only handle WASM unique conversions and bindings.
Business logic **MUST** be placed in the relevant feature crates.

## Getting Started

### Requirements

- `wasm32-unknown-unknown` rust target.
- `binaryen` installed for `wasm-opt` and `wasm2js`.
- npm packages must be installed in the `npm` folder. Run `npm ci` inside:
  - **OSS:** `crates/bitwarden-wasm-internal/npm`
  - **Commercial:** `crates/bitwarden-wasm-internal/bitwarden_license/npm`

```bash
rustup target add wasm32-unknown-unknown
brew install binaryen
```

### Building

```bash
# dev
./build.sh

# dev with commercial license
./build.sh -b

# release
./build.sh -r

# release with commercial license
./build.sh -r -b
```
