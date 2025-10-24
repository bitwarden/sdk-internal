# Bitwarden Internal SDK

Rust SDK centralizing business logic. You're reviewing code as a senior Rust engineer mentoring
teammates.

## Client Pattern

PasswordManagerClient ([bitwarden-pm](crates/bitwarden-pm/src/lib.rs)) wraps
[bitwarden_core::Client](crates/bitwarden-core/src/client/client.rs) and exposes sub-clients:
`auth()`, `vault()`, `crypto()`, `sends()`, `generators()`, `exporters()`.

**Lifecycle**

- Init → Lock/Unlock → Logout (drops instance). Memento pattern for state resurrection.

**Storage**

- Consuming apps use `HashMap<UserId, PasswordManagerClient>`.

## Issues necessitating comments

**Auto-generated code changes**

- Changes to `bitwarden-api-api/` or `bitwarden-api-identity/` are generally discouraged. These are
  auto-generated from swagger specs.

**Secrets in logs/errors**

- Do not log keys, passwords, or vault data in logs or error paths. Redact sensitive data.

**Business logic in WASM**

- `bitwarden-wasm-internal` contains only thin bindings. Move business logic to feature crates.

**Unsafe without justification**

- Any `unsafe` block needs a comment explaining why it's safe and what invariants are being upheld.

**Changes to `bitwarden-crypto/` core functionality**

- Generally speaking, this crate should not be modified. Changes need a comment explaining why.

**New crypto algorithms or key derivation**

- Detailed description, review and audit trail required. Document algorithm choice rationale and
  test vectors.

**Encryption/decryption modifications**

- Verify backward compatibility. Existing encrypted data must remain decryptable.

**Breaking serialization**

- Backward compatibility required. Users must decrypt vaults from older versions.

**Breaking API changes**

- Document migration path for clients.

## References

- [SDK Architecture](https://contributing.bitwarden.com/architecture/sdk/)
- [Architectural Decision Records (ADRs)](https://contributing.bitwarden.com/architecture/adr/)
- [Contributing Guidelines](https://contributing.bitwarden.com/contributing/)
- [Setup Guide](https://contributing.bitwarden.com/getting-started/sdk/internal/)
- [Code Style](https://contributing.bitwarden.com/contributing/code-style/)
- [Security Whitepaper](https://bitwarden.com/help/bitwarden-security-white-paper/)
- [Security Definitions](https://contributing.bitwarden.com/architecture/security/definitions)
