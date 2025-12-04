# Bitwarden Internal SDK

Cross-platform Rust SDK implementing Bitwarden's core business logic.

**Rust Edition:** The SDK targets the
[2024](https://doc.rust-lang.org/nightly/edition-guide/rust-2024/index.html) edition of Rust.

**Crate documentation**: Before working in any crate, read available documentation: `CLAUDE.md` for
critical rules, `README.md` for architecture, `examples/` for usage patterns, and `tests/` for
integration tests. **Before making changes or reviewing code, review relevant examples and tests for
the specific functionality you're modifying.**

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

- **DO NOT modify** without careful consideration - backward compatibility is critical
- **KeyStoreContext**: Never hold across await points
- Naming: `derive_` for deterministic key derivation, `make_` for non-deterministic generation
- Use `bitwarden_crypto::safe` module first (password-protected key envelope, data envelope) instead
  of more low-level primitives
- IMPORTANT: Use constant time equality checks
- Do not expose low-level / hazmat functions from the crypto crate.
- Do not expose key material from the crypto crate, use key references in the key store instead

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

## Development Workflow

**Build & Test:**

- `cargo check --all-features --all-targets` - Quick validation
- `cargo test --workspace --all-features` - Full test suite

**Format & Lint:**

- `cargo +nightly fmt --workspace` - Code formatting
- Use `cargo clippy` to lint code and catch common mistakes

**WASM Testing:**

- `cargo test --target wasm32-unknown-unknown --features wasm -p bitwarden-error -p bitwarden-threading -p bitwarden-uuid` -
  WASM-specific tests

## References

- [SDK Architecture](https://contributing.bitwarden.com/architecture/sdk/)
- [Architectural Decision Records (ADRs)](https://contributing.bitwarden.com/architecture/adr/)
- [Contributing Guidelines](https://contributing.bitwarden.com/contributing/)
- [Setup Guide](https://contributing.bitwarden.com/getting-started/sdk/internal/)
- [Code Style](https://contributing.bitwarden.com/contributing/code-style/)
- [Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)
- [Security Definitions](https://contributing.bitwarden.com/architecture/security/definitions)
- [Rust 2024 Edition Guide](https://doc.rust-lang.org/edition-guide/rust-2024/)
