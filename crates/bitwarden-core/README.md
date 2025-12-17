# Bitwarden Core

Core infrastructure crate providing the base `Client` type - a container for runtime persistent data
and shared infrastructure that feature crates extend via extension traits. For an introduction to
the SDK architecture, see the
[SDK Architecture](https://contributing.bitwarden.com/architecture/sdk/) documentation.

> [!WARNING] Do not add business logic or feature-specific functionality to this crate. Use feature
> crates instead.

## `Client` Structure

The `Client` type serves as a **container for runtime persistent data**, which is intended to
persist for the lifetime of the SDK instance. Think of this as "dependency injection" for the SDK
instance. It should only contain:

1. **User identity**:
   - `UserId` - Ensures each client is immutably associated with one user
2. **Security state**:
   - `KeyStore` - Secure in-memory key management
3. **Network state**:
   - `ApiClient`/`ApiConfigurations` - HTTP client initialized once and reused
   - `Tokens` enum - Includes `ClientManagedTokens` trait and `SdkManagedTokens` struct for access
     token management
4. **Storage state**:
   - Database/state repository registration

**Plain data** (tokens, flags, login info, profile data) should be accessed through `Repository`
implementations, not stored directly in `Client`. Historical fields exist due to incremental
migration - they will be moved to repositories over time.

### `Client` vs `InternalClient`

- `Client` is a lightweight wrapper around `Arc<InternalClient>`
- `Arc` enables cheap cloning for FFI bindings (owned copies point to same underlying instance)
- `InternalClient` originally hid internal APIs from Secrets Manager, but this separation becomes
  less important as functionality moves to feature crates

## Extension Pattern

Feature crates extend `Client` via extension traits. This allows the underlying implementation to be
internal to the crate with only the public API exposed through the `Client` struct. Below is an
example of a generator extension for the `Client` struct.

> [!IMPORTANT] Do not add feature functionality to `Client` itself.

```rust,ignore
use bitwarden_core::Client;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Generator extension client that wraps the base Client
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct GeneratorClient {
    client: Client,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl GeneratorClient {
    fn new(client: Client) -> Self {
        Self { client }
    }

    /// Example method that uses the underlying Client
    pub fn password(&self, input: PasswordGeneratorRequest) -> Result<String, PasswordError> {
        // Implementation details...
        password(input)
    }
}

/// Extension trait which exposes `generator()` method on the `Client` struct
pub trait GeneratorClientsExt {
    fn generators(&self) -> GeneratorClient;
}

impl GeneratorClientsExt for Client {
    fn generators(&self) -> GeneratorClient {
        GeneratorClient::new(self.clone())
    }
}

// Usage:
// let password = client.generators().password(request)?;
```
