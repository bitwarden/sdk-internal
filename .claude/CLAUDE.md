# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Bitwarden Internal SDK

Cross-platform Rust SDK implementing Bitwarden's core business logic.

**Rust Edition:** The SDK targets the
[2024](https://doc.rust-lang.org/nightly/edition-guide/rust-2024/index.html) edition of Rust.

**Rust Version:** Locked to 1.91.1 via `rust-toolchain.toml`. Nightly toolchain
(nightly-2025-08-18) required for formatting and unused dependency checks.

**Crate documentation**: Before working in any crate, read available documentation: `CLAUDE.md` for
critical rules, `README.md` for architecture, `examples/` for usage patterns, and `tests/` for
integration tests. **Before making changes or reviewing code, review relevant examples and tests for
the specific functionality you're modifying.** **Crypto-related changes require integration tests per the Integration Testing Requirements section.**

## Architecture Overview

Monorepo crates organized in **four architectural layers**:

### 1. Foundation Layer

- **bitwarden-crypto**: Cryptographic primitives and protocols, key store for securely working with
  keys held in memory.
- **bitwarden-state**: Type-safe Repository pattern for SDK state (client-managed vs SDK-managed)
- **bitwarden-threading**: ThreadBoundRunner for !Send types in WASM/GUI contexts (uses PhantomData
  marker)
- **bitwarden-ipc**: Type-safe IPC framework with pluggable encryption/transport
- **bitwarden-error**: Error handling across platforms (basic/flat/full modes via proc macro)
- **bitwarden-encoding**, **bitwarden-uuid**: Encoding and UUID utilities

### 2. Core Infrastructure

- **bitwarden-core**: Base Client struct extended by feature crates via extension traits. **DO NOT
  add functionality here - use feature crates instead.**
  - **bitwarden-api-api**, **bitwarden-api-identity**: Auto-generated API clients (**DO NOT edit -
    regenerate from OpenAPI specs**)

### 3. Feature Implementations

- **bitwarden-pm**: PasswordManagerClient wrapping core Client, exposes sub-clients: `auth()`,
  `vault()`, `crypto()`, `sends()`, `generators()`, `exporters()`
  - Lifecycle: Init → Lock/Unlock → Logout (drops instance)
  - Storage: Apps use `HashMap<UserId, PasswordManagerClient>`
- **bitwarden-vault**: Vault item models, encryption/decryption and management
- **bitwarden-collections**: Collection models, encryption/decryption and management
- **bitwarden-auth**: Authentication (send access tokens)
- **bitwarden-send**: Encrypted temporary secret sharing
- **bitwarden-generators**: Password/passphrase generators
- **bitwarden-ssh**: SSH key generation/import
- **bitwarden-exporters**: Vault export/import with multiple formats
- **bitwarden-fido**: FIDO2 two-factor authentication

### 4. Cross-Platform Bindings

- **bitwarden-uniffi**: Mobile bindings (Swift/Kotlin) via UniFFI
  - Structs: `#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]`
  - Enums: `#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]`
  - Include `uniffi::setup_scaffolding!()` in lib.rs
- **bitwarden-wasm-internal**: WebAssembly bindings (**thin bindings only - no business logic**)
  - Structs: `#[derive(Serialize, Deserialize)]` with
    `#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]`

## Critical Patterns & Rules

### Cryptography (bitwarden-crypto)

- **ALL cryptographic operations MUST live in bitwarden-crypto** - Never implement encryption,
  decryption, hashing, key derivation, or any other cryptographic primitives outside this crate.
  Feature crates should only consume bitwarden-crypto APIs.
- **DO NOT modify** without careful consideration - backward compatibility is critical
- **KeyStoreContext**: Never hold across await points
- Naming: `derive_` for deterministic key derivation, `make_` for non-deterministic generation
- Use `bitwarden_crypto::safe` module first (password-protected key envelope, data envelope) instead
  of more low-level primitives
- IMPORTANT: Use constant time equality checks
- Do not expose low-level / hazmat functions from the crypto crate.
- Do not expose key material from the crypto crate, use key references in the key store instead

### Integration Testing Requirements

**CRITICAL**: Changes to cryptographic operations MUST include integration tests that exercise the complete flow across crate boundaries. Integration tests verify that components work together correctly, not just in isolation.

#### Definition: Integration vs Unit Tests

- **Unit tests** (`#[cfg(test)] mod tests` in source files): Test individual functions or modules in isolation, often using mocks
- **Integration tests** (separate `tests/` directory): Test complete workflows that span multiple modules or crates, using real implementations

**Important**: Integration tests for crypto operations test SDK component integration (crypto + core + auth crates working together), NOT integration with external services. These tests run without a live server.

Integration tests MUST:
- Live in a `tests/` directory at the crate root (not in `src/`)
- Import crates as external dependencies (e.g., `use bitwarden_core::Client;`)
- **Test ONLY public APIs** - Never test internal/private functions or implementation details
- Exercise the full API surface as clients would use it (e.g., `client.auth().make_register_keys()`, `client.crypto().initialize_user_crypto()`)
- Test complete workflows from initialization through execution
- Include both success and failure cases
- Document what they're testing with clear comments
- **Use `Client::new(None)` for crypto-only tests** (no server needed)
- **Use `wiremock` mocks for API tests** (from `bitwarden-test` crate) when server responses are needed

Integration tests MUST NOT:
- Test private functions, internal helpers, or implementation details
- Bypass public APIs to access internals
- Import crate internals with `use crate_name::internal::*;`

#### Required Integration Tests

The following crypto operations REQUIRE integration tests before merging:

**1. User Registration & Key Generation**
- User registration with password (`make_register_keys`)
- TDE (Trust Device Encryption) registration (`make_user_tde_registration`)
- Key pair generation and verification
- Example: `crates/bitwarden-core/tests/register.rs`

**2. User Crypto Initialization**
- All `InitUserCryptoMethod` variants:
  - Password-based initialization
  - Master password unlock
  - Decrypted key (biometric/never lock)
  - PIN unlock (legacy)
  - PIN envelope unlock (password-protected envelope)
  - Auth request (passwordless)
  - Device key (TDE)
  - Key connector
- Organization crypto initialization

**3. PIN Operations**
- PIN enrollment (`enroll_pin`)
- PIN-protected key envelope creation and unsealing
- PIN unlock flow (complete: enroll → lock → unlock with PIN)
- PIN validation against encrypted user keys

**4. Password & KDF Operations**
- Password hash generation and validation
- KDF updates (`make_update_kdf`) with both PBKDF2 and Argon2id
- Password changes (`make_update_password`)
- Master password re-encryption flows

**5. Key Rotation & Crypto V2**
- User crypto V2 key generation (`make_v2_keys_for_v1_user`)
- Account key rotation (`get_v2_rotated_account_keys`)
- Migration paths between crypto versions

**6. Device Trust & Authentication**
- Device key generation (`trust_device` flag in registration)
- Device key verification
- Auth request flows with device keys

**7. Safe Module Operations**
- `PasswordProtectedKeyEnvelope`: seal, unseal, reseal operations
- `DataEnvelope`: seal, unseal with content encryption keys
- These demonstrate proper usage patterns for crypto abstractions

**8. Admin Password Reset & Organization Keys**
- Admin password reset enrollment
- Organization key wrapping and unwrapping
- Key sharing with organization public keys

#### When Integration Tests Are Required

Integration tests are MANDATORY when:

1. **Modifying crypto primitives** in `bitwarden-crypto` that are used by higher-level crates
2. **Adding new cryptographic operations** or authentication methods
3. **Changing key derivation, encryption, or decryption logic** that affects stored data
4. **Modifying the KeyStore** or key management system
5. **Updating serialization formats** for encrypted data or keys
6. **Implementing new authentication flows** or unlock methods
7. **Changing backward compatibility** of cryptographic operations

#### Integration Test Patterns

**Pattern 1: Crypto-Only Integration Test (No Server)**

Most crypto integration tests don't need external dependencies. They test SDK components working together:

```rust
//! Integration tests for [feature description]

/// Tests [specific workflow] end-to-end
#[cfg(feature = "internal")]
#[tokio::test]
async fn test_complete_workflow() {
    use bitwarden_core::{Client, ...};
    use bitwarden_crypto::{Kdf, ...};

    // 1. Setup: Create client WITHOUT server connection
    let client = Client::new(None); // <-- No HTTP client needed
    let email = "test@bitwarden.com";
    let password = "secure_password";

    // 2. Execute: Run the complete workflow (crypto operations only)
    let result = client.crypto().operation().execute().await.unwrap();

    // 3. Verify: Check that state is correct
    assert!(result.field.is_some());

    // 4. Test dependent operations
    let next_result = client.crypto().dependent_operation().await.unwrap();
}
```

**Pattern 2: Integration Test with Mocked API**

When tests need to verify API communication, use `wiremock` to mock server responses:

```rust
use bitwarden_test::start_api_mock;
use wiremock::{Mock, ResponseTemplate};

#[cfg(feature = "internal")]
#[tokio::test]
async fn test_operation_with_api() {
    // Setup mock server
    let mock = Mock::given(wiremock::matchers::method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(/* response */));

    let (server, config) = start_api_mock(vec![mock]).await;

    // Create client with mocked API
    let client = Client::new(Some(config));

    // Test operation that calls API
    let result = client.operation().execute().await.unwrap();

    // Verify behavior
    assert!(result.is_ok());

    // MockServer is automatically dropped and verifies all expected calls were made
}
```

**Key Principles**:
- **Test through public APIs only** - Integration tests verify public functionality that clients use, not internal implementation
- **Component integration, not service integration** - Tests verify SDK crates work together, not external service communication
- **Client perspective** - Write tests as if you're a client consuming the SDK

See examples:
- `crates/bitwarden-core/tests/register.rs` - Crypto-only integration test (no server)
- `crates/bitwarden-test/src/api.rs` - Helper for mocking API when needed
- `crates/bitwarden-crypto/examples/` - Usage patterns for crypto operations

#### Enforcement

- **Code Review**: Reviewers MUST verify integration tests exist for crypto changes
- **Claude Code**: When detecting crypto changes, Claude should proactively ask: "This change affects cryptographic operations. According to CLAUDE.md, integration tests are required. Should I help create integration tests?"
- **PR Checklist**: PRs affecting crypto operations must include:
  - [ ] Integration tests added or updated
  - [ ] Tests cover success and failure cases
  - [ ] Tests verify backward compatibility where applicable

#### What Does NOT Require Integration Tests

- Pure documentation changes
- Refactoring that doesn't change behavior (proven by existing tests passing)
- Changes confined to single functions with unit test coverage
- Non-crypto feature changes in other crates
- **Internal/private implementation changes** that don't affect public APIs

#### Integration Test Do's and Don'ts

**DO:**
✅ Test through public client APIs (`client.auth()`, `client.crypto()`, etc.)
✅ Test workflows that clients will actually use
✅ Test from the perspective of an SDK consumer
✅ Import only public types and traits
✅ Verify end-to-end behavior across crate boundaries

**DON'T:**
❌ Test private functions or internal helpers (use unit tests for those)
❌ Bypass public APIs to access internals
❌ Test implementation details that could change without affecting behavior
❌ Import internal modules (e.g., `use bitwarden_crypto::internal::*;`)
❌ Make assertions about internal state that isn't exposed publicly

### State Management (bitwarden-state)

- **Client-managed**: App and SDK share data pool (requires manual setup)
- **SDK-managed**: SDK exclusively handles storage (migration-based, ordering is critical)
- Register types with `register_repository_item!` macro
- Type safety via TypeId-based type erasure with runtime downcast checks

### Threading (bitwarden-threading)

- Use ThreadBoundRunner for !Send types (WASM contexts, GUI handles, Rc<T>)
- Pins state to thread via spawn_local, tasks via mpsc channel
- PhantomData<\*const ()> for !Send marker (zero-cost)

### Error Handling (bitwarden-error-macro)

- Three modes: **basic** (string), **flat** (variant), **full** (structure)
- Generates FlatError trait, WASM bindings, TypeScript interfaces, UniFFI errors
- Conditional code generation via cfg! for WASM

### Security Requirements

- **Never log** keys, passwords, or vault data in logs or error paths
- **Redact sensitive data** in all error messages
- **Unsafe blocks** require comments explaining safety and invariants
- **Encryption/decryption changes** must maintain backward compatibility (existing encrypted data
  must remain decryptable)
- **Breaking serialization** strongly discouraged - users must decrypt vaults from older versions

### API Changes

- **Breaking changes**: Automated detection via cross-repo workflow (see commit 9574dcc1)
- TypeScript compilation tested against `clients` repo on PR
- Document migration path for clients

### Regenerating API Bindings

**DO NOT manually edit** `bitwarden-api-api` or `bitwarden-api-identity` crates - they are
auto-generated from OpenAPI specs.

To regenerate API bindings:

1. Generate swagger docs from the server repository:
   ```bash
   pwsh ./dev/generate_openapi_files.ps1
   ```
2. Run generation script from SDK root:
   ```bash
   ./support/build-api.sh
   ```
3. **Important**: Do NOT commit changes to `Cargo.toml` made by the generation process - revert
   those changes before creating a PR

The generation uses customized templates in `support/openapi-template/` to resolve known issues with
the rust generator.

## Development Workflow

**Build & Test:**

- `cargo build` - Standard build
- `cargo check --all-features --all-targets` - Quick validation
- `cargo test --workspace --all-features` - Full test suite
- `cargo nextest run --all-features` - Faster parallel test runner (requires separate installation:
  `cargo install cargo-nextest --locked`)
- Run tests for specific package: `cargo test -p bitwarden-crypto --all-features`
- **Integration test requirement**: Changes to crypto operations require integration tests in `tests/` directories - see "Integration Testing Requirements" section

**Format & Lint:**

The repository requires strict formatting and linting before merging. Commands match CI checks:

- `cargo +nightly fmt --workspace` - Code formatting (nightly required)
- `cargo +nightly udeps --workspace --all-features` - Find unused dependencies (nightly required)
- `cargo clippy --all-features --all-targets` - Lint for common mistakes (set `RUSTFLAGS="-D
  warnings"` to fail on warnings)
- `cargo dylint --all -- --all-features --all-targets` - Custom lints (requires separate
  installation: `cargo install cargo-dylint --locked`)
- `cargo sort --workspace --grouped --check` - Check dependency ordering (requires separate
  installation: `cargo install cargo-sort`)
- `npm run lint` - Run prettier checks on non-Rust files
- `npm run prettier` - Auto-fix prettier formatting

**WASM Testing:**

- `cargo test --target wasm32-unknown-unknown --features wasm -p bitwarden-error -p bitwarden-threading -p bitwarden-uuid` -
  WASM-specific tests

**Background Code Checking (Optional):**

- Install bacon: `cargo install bacon --locked`
- Run `bacon` in project root for continuous background checking
- Run `bacon -l` to list available tasks (check, clippy, test, doc, etc.)

## References

- [SDK Architecture](https://contributing.bitwarden.com/architecture/sdk/)
- [Architectural Decision Records (ADRs)](https://contributing.bitwarden.com/architecture/adr/)
- [Contributing Guidelines](https://contributing.bitwarden.com/contributing/)
- [Setup Guide](https://contributing.bitwarden.com/getting-started/sdk/internal/)
- [Code Style](https://contributing.bitwarden.com/contributing/code-style/)
- [Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)
- [Security Definitions](https://contributing.bitwarden.com/architecture/security/definitions)
- [Rust 2024 Edition Guide](https://doc.rust-lang.org/edition-guide/rust-2024/)
