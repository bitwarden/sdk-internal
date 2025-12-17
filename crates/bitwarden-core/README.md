# Bitwarden Core

Core infrastructure crate providing the base `Client` type - a container for runtime persistent data
and shared infrastructure that feature crates extend via extension traits. For an introduction to the
SDK architecture, see the [SDK Architecture](https://contributing.bitwarden.com/architecture/sdk/)
documentation.

> **Warning**: Do not add business logic or feature-specific functionality to this crate. Use feature crates instead.

## Architecture

### Client Structure

The `Client` type serves as a **container for runtime persistent data**, which is intended to persist for the lifetime of the SDK instance. Think of this as "dependency injection" for the SDK instance. It should only contain:

1. **User identity**:
   - `UserId` - Ensures each client is immutably associated with one user
2. **Security state**:
   - `KeyStore` - Secure in-memory key management
3. **Network state**:
   - `ApiClient`/`ApiConfigurations` - HTTP client initialized once and reused
   - `TokenRenew` trait - Implemented by `bitwarden-auth` crate for API client token renewal
4. **Storage state**:
   - Database/state repository registration

**Plain data** (tokens, flags, login info, profile data) should be accessed through `Repository`
implementations, not stored directly in `Client`. Historical fields exist due to incremental
migration - they will be moved to repositories over time.

### Client vs InternalClient

- `Client` is a lightweight wrapper around `Arc<InternalClient>`
- `Arc` enables cheap cloning for FFI bindings (owned copies point to same underlying instance)
- `InternalClient` originally hid internal APIs from Secrets Manager, but this separation becomes less important as functionality moves to feature crates

### Extension Pattern

Feature crates extend `Client` via traits (e.g., `PasswordManagerClient` wraps `Client` and exposes `vault()`, `generators()` sub-clients).

**Do not add feature functionality to `Client` itself.**