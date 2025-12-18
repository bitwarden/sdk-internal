# Bitwarden Core

Core infrastructure crate providing the base `Client` type - a container for runtime persistent data
and shared infrastructure that feature crates extend via extension traits. For an introduction to
the SDK architecture, see the
[SDK Architecture](https://contributing.bitwarden.com/architecture/sdk/) documentation.

> [!WARNING] Do not add business logic or feature-specific functionality to this crate. Use feature
> crates instead.

## `Client` structure

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

### Extension pattern

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

## API requests

One of the responsibilities of the `Client` is managing and exposing the `ApiClient` instances for our API and Identity back-end services, which should be used to make HTTP requests.

These `ApiClient`s should be accessed through the `ApiConfigurations` struct that is returned from the `get_api_configurations()` function. `get_api_configurations()` also refreshes the authentication token if required.

```rust
// Example API call
let api_config: &ApiConfigurations = client.get_api_configurations().await;
let api_client: &bitwarden_api_api::apis::ApiClient = api_config.ApiClient;
let response = api_client.ciphers_api.get_all().await;
``` 

### Server API bindings

To make the requests, we use auto-generated bindings whenever possible. We use `openapi-generator` to generate the Rust bindings from the server OpenAPI specifications. These bindings are regularly updated to ensure they stay in sync with the server.

The bindings are exposed as multiple crates, one for each backend service:
- [`bitwarden-api-api`](../bitwarden-api-api/README.md): For the `Api` service that contains most of the server side functionality.
- [`bitwarden-api-identity`](../bitwarden-api-identity/README.md): For the `Identity` service that is used for authentication.

When performing any API calls the goal is to use the generated bindings as much as possible. This ensures any changes to the server are accurately reflected in the SDK. The generated bindings are stateless, and always expects to be provided a Configuration instance. The SDK exposes these under the get_api_configurations function on the Client struct. 

You should not expose the request and response models of the auto-generated bindings and should instead define and use your own models. This ensures the server request / response models are decoupled from the SDK models and allows for easier changes in the future without breaking backwards compatibility.

We recommend using either the `From` or `TryFrom` conversion traits depending on if the conversion requires error handling or not. Below are two examples of how this can be done:

```rust
impl TryFrom<bitwarden_api_api::models::CipherLoginUriModel> for LoginUri {
    type Error = Error;

    fn try_from(uri: bitwarden_api_api::models::CipherLoginUriModel) -> Result<Self> {
        Ok(Self {
            uri: EncString::try_from_optional(uri.uri)?,
            r#match: uri.r#match.map(|m| m.into()),
            uri_checksum: EncString::try_from_optional(uri.uri_checksum)?,
        })
    }
}

impl From<bitwarden_api_api::models::UriMatchType> for UriMatchType {
    fn from(value: bitwarden_api_api::models::UriMatchType) -> Self {
        match value {
            bitwarden_api_api::models::UriMatchType::Domain => Self::Domain,
            bitwarden_api_api::models::UriMatchType::Host => Self::Host,
            bitwarden_api_api::models::UriMatchType::StartsWith => Self::StartsWith,
            bitwarden_api_api::models::UriMatchType::Exact => Self::Exact,
            bitwarden_api_api::models::UriMatchType::RegularExpression => Self::RegularExpression,
            bitwarden_api_api::models::UriMatchType::Never => Self::Never,
        }
    }
}
```

### Updating bindings after a server API change

When the API exposed by the server changes, new bindings will need to be generated to reflect this change for consumption in the SDK. This includes adding new fields to server request / response models, removing fields from models, or changing types of models.

This can be done the following ways:
1. Run the `Update API Bindings` workflow in the `sdk-internal` repo.
2. Wait for an automatic binding update to run, which is scheduled every 2 weeks.

Both of these will generate a PR that will require approval from any teams whose owned code is affected by the binding updates.

> [!IMPORTANT]
> Bindings should **not** be updated manually as part of the changes to consume the new server API in the SDK. Doing so manually risks causing conflicts with the auto-generated bindings and causing more work in the future to address it.