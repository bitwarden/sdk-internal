This document provides explicit instructions for Copilot Agent to follow when working with this
repository. It outlines the coding standards, project structure, and best practices to ensure
high-quality contributions that align with the repository's goals and maintainability standards.

## Repository Overview

This is the Bitwarden SDK - a cross-platform library written in Rust that implements core business
logic for the Bitwarden applications.

The repository is organized as a **monorepo** containing multiple libraries (`crates`) located under
`bitwarden_license` and `crates`. Some notable crates include:

- **`bitwarden-core`** - Contains the underlying functionality of the SDK. This includes a Client
  struct. Other crates in the SDK depend on bitwarden-core and provide extensions to the Client
  struct to implement specific domains. **Avoid adding functionality to this crate and prefer to
  implement it in feature crates.**
- **`bitwarden-crypto`** - Cryptographic primitives and key management
- **`bitwarden-api-*`** - Auto-generated API bindings (DO NOT edit manually)
- **`bitwarden-uniffi`** - Mobile bindings wrapper
- **`bitwarden-wasm-internal`** - WebAssembly bindings

## Feature Flags

The SDK uses the following rust feature flags for language bindings.

- `uniffi` - Mobile bindings (Swift/Kotlin) via UniFFI
- `wasm` - WebAssembly bindings with wasm-bindgen

### Core Architecture

The Client struct is the main entry point for the SDK and represents a single account instance. Any
action that needs to be performed on the account is generally done through the Client struct. This
allows the internals to be hidden from the consumer and provides a clear API.

We can extend the Client struct using extension traits in feature crates. This allow the underlying
implementation to be internal to the crate with only the public API exposed through the Client
struct. Below is an example of a generator extension for the Client struct.

Crates usually contains one or multiple `<domain>_client.rs` files which contains a Client struct
that implements the core business logic for the domain.

```rust
/// Generator extension for the Client struct
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct GeneratorClient {
    client: Client,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl GeneratorClient {
    fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Generates a password based on the provided request.
    pub fn password(&self, input: PasswordGeneratorRequest) -> Result<String, PasswordError> {
        password(input)
    }

}

// Extension which exposes `generator` method on the `Client` struct.
pub trait GeneratorClientExt {
    fn generator(self) -> GeneratorClient;
}

impl GeneratorClientExt for Client {
    fn generator(self) -> GeneratorClient {
        GeneratorClient::new(self)
    }
}
```

### Cross-Platform Bindings

#### UniFFI

UniFFI is used for mobile bindings (Swift/Kotlin). Crates must include the following in `lib.rs` to
enable UniFFI support.

```rust
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
```

Structs and enums that are exposed through a domain client must be derive:

- Structs: `#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]`.
- Enums: `#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]`.

#### WASM

WASM is used for web bindings. Structs and enums that are exposed through a domain client should
derive tsify.

```rust
// Add import to top of file
#[cfg(feature = "wasm")]
use {tsify::Tsify, wasm_bindgen::prelude::*};

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]
pub struct ExampleStruct {
    // Fields here
}
```

## Development Workflow

### Building & Testing

Use the following commands to build and test the SDK:

- `cargo check --all-features --all-targets` to quickly verify code is valid.
- `cargo test --workspace --all-features` to run tests

### Formatting & Linting

Before committing code, ensure it is formatted and linted:

- `cargo +nightly fmt --workspace` for formatting
- `cargo clippy --workspace` for linting
