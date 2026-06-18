# bitwarden-importers

Internal crate implementing format-specific vault importers for the Bitwarden SDK. Do not use
directly.

Exposes `client.importers()` ([`ImporterClient`]) with:

- `import_kdbx` — parses a KeePass KDBX (`.kdbx`) database (3.1 + 4, via the `keepass` crate),
  encrypts the entries for the user's personal vault or a given organization, and submits them to
  the server's import endpoint. Returns per-type counts.
- `keeper_crypto` — a stateless [`keeper::KeeperCryptoClient`] exposing Keeper's "direct" importer
  cryptography (see below).

## Keeper direct importer

The Keeper "direct" importer logs into Keeper's API and decrypts the vault on-device. Its access
layer is being ported from TypeScript (`clients` repo) into the [`keeper`] module incrementally
(strangler-fig). The first piece, [`keeper::crypto`], implements **Keeper's** competitor wire
formats — unauthenticated AES-CBC ("aes-v1"), AES-GCM with a prepended nonce ("aes-v2"), RSA
PKCS#1 v1.5, an ECDH-P256 → SHA-256 → AES-GCM scheme, and Keeper's custom `encryptionParams` blob.
These are **not** Bitwarden cryptography and deliberately do not live in `bitwarden-crypto`; they
reuse `bitwarden_crypto` where a primitive is standard (PBKDF2) and the RustCrypto crates otherwise.
WASM ([`keeper::KeeperCryptoClient`]) and UniFFI bindings let the still-TypeScript access layer call
the Rust implementation while the rest is migrated.

## Architecture

The shared "interchange" model (`ImportingCipher`, `CipherType`, `Login`/`Card`/…, and the
`From<ImportingCipher> for CipherView` bridge plus `encrypt_import`) lives in `bitwarden-exporters`
and is reused here — this crate depends on `bitwarden-exporters`. CXF import remains in
`bitwarden-exporters` because it is one half of a bidirectional codec.
