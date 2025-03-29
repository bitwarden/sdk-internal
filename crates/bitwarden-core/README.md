# Bitwarden Core

Contains core functionality used by the feature crates. For an introduction to the Bitwarden SDK and
the `bitwarden-core` create please refer to the
[SDK Architecture](https://contributing.bitwarden.com/architecture/sdk/) documentation.

<div class="warning">
Generally you should <b>not</b> find yourself needing to edit this crate! When possible, please use the feature crates instead.
</div>

## Features

- `internal` - Internal unstable APIs that should only be consumed by internal Bitwarden clients.
- `no-memory-hardening` - Disables `bitwarden-crypto` memory hardening.
- `secrets` - Secrets Manager specific functionality.
- `uniffi` - Mobile bindings.
- `wasm` - WebAssembly bindings.
