---
paths:
  - "crates/bitwarden-crypto/**"
  - "crates/bitwarden-organization-crypto/**"
---

# Cryptography crates

Changes here affect every Bitwarden client. Backward compatibility is non-negotiable: data encrypted
by older releases must remain decryptable, so treat serialization and format changes as forbidden
unless explicitly coordinated.

- Prefer the `bitwarden_crypto::safe` module (password-protected key envelope, data envelope) over
  low-level primitives.
- Do not expose hazmat functions or raw key material from these crates — hand out key references
  into the `KeyStore` instead.
- Never hold a `KeyStoreContext` across an `await` point.
- Naming: `derive_*` for deterministic key derivation, `make_*` for random generation.
- Compare secrets with constant-time equality.
- These are foundation crates: they must not depend on `bitwarden-core` or anything that depends on
  it.
