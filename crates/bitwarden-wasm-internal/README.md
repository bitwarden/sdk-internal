# bitwarden-wasm-internal

**Note:** This is only for internal use. Bitwarden will not provide any support for this crate.

Bitwarden WASM internal exposes WebAssembly bindings for the Bitwarden SDK. This crate should
contain no logic but rather only handle WASM unique conversions and bindings. Business logic
**MUST** be placed in the relevant feature crates.

## Getting Started

### Requirements

- `wasm32-unknown-unknown` rust target.
- `wasm-bindgen-cli` installed.
- `binaryen` installed for `wasm-opt` and `wasm2js`.

```bash
rustup target add wasm32-unknown-unknown
cargo install -f wasm-bindgen-cli
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
