# Bitwarden Internal SDK

Rust SDK centralizing business logic **Internal use only**

## Client Pattern

PasswordManagerClient ([bitwarden-pm](crates/bitwarden-pm/src/lib.rs)) wraps
[bitwarden_core::Client](crates/bitwarden-core/src/client/client.rs) and exposes sub-clients:
`auth()`, `vault()`, `crypto()`, `sends()`, `generator()`, `exporters()`.

**Lifecycle**: Init → Lock/Unlock → Logout (drops instance). Memento pattern for state resurrection.

**Storage**: Consuming apps use `HashMap<UserId, PasswordManagerClient>`.

## Crate Organization

- `bitwarden-core` - Core Client struct (avoid editing, use feature crates)
- `bitwarden-crypto` - Crypto primitives (edit with extreme care, multi-team ownership)
  - `derive_*` = deterministic key derivation, `make_*` = non-deterministic generation
  - Memory zeroed on drop by default
- `bitwarden-{auth,vault,send,generators}` - Domain features
- `bitwarden-uniffi` - Mobile bindings (no lifetimes in FFI types)
- `bitwarden-wasm-internal` - Web bindings (no logic, only conversions)
- `bitwarden-api-*` - Auto-generated (regenerate via `./support/build-api.sh`, revert Cargo.toml)

## Non-Obvious Constraints

- Clippy allows `.unwrap()` and `.expect()` in tests only
- `bitwarden-wasm-internal` must remain logic-free (business logic belongs in feature crates)
- Serializable crypto representations must maintain backward compatibility indefinitely
