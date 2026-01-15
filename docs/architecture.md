# Architecture Documentation

## application

- `crates/bw/README.md`: A work-in-progress rust rewrite of the Bitwarden CLI.

## bindings

- `crates/bitwarden-api-api/README.md`: Auto-generated API bindings for Bitwarden API service (**DO
  NOT edit - regenerate from OpenAPI specs**)
- `crates/bitwarden-api-identity/README.md`: Auto-generated API bindings for Bitwarden Identity
  service (**DO NOT edit - regenerate from OpenAPI specs**)
- `crates/bitwarden-api-key-connector/README.md`: Auto-generated API bindings for Bitwarden Key
  Connector service. Note: These are manually maintained.
- `crates/bitwarden-uniffi/README.md`: Mobile bindings for iOS (swift) and Android (kotlin) which
  exposes the Bitwarden Password Manager to our mobile applications using UniFFI.
- `crates/bitwarden-wasm-internal/README.md`: WebAssembly bindings for the Bitwarden SDK, consumed
  by the internal Bitwarden web clients. Thin bindings only - no business logic.

## feature

- `bitwarden_license/bitwarden-sm/README.md`: Bitwarden Secrets Manager
- `crates/bitwarden-auth/README.md`: Contains the implementation of the auth functionality for the
  Bitwarden Password Manager.
- `crates/bitwarden-collections/README.md`: Defines the data model for collections both encrypted
  and decrypted. It also handles conversions between those two states by implementing `Encryptable`.
  It also provides `Tree` struct which allows all structs implementing `TreeItem` to be represented
  in a tree structure along with functions to access each node.
- `crates/bitwarden-exporters/README.md`: Export and import support for Bitwarden Password Manager
  through various formats.
- `crates/bitwarden-fido/README.md`: FIDO2 (Passkey) implementation for Bitwarden Password Manager.
- `crates/bitwarden-generators/README.md`: Various generators implementations for the Bitwarden
  Password Manager. Such as password, passphrase and username generation.
- `crates/bitwarden-pm/README.md`: PasswordManagerClient wrapping core Client, exposes sub-clients
  for auth, vault, crypto, sends, generators, and exporters.
- `crates/bitwarden-policies/README.md`: Admin console owned policy code.
- `crates/bitwarden-send/README.md`: All Bitwarden Send related domain logic. Bitwarden Send allows
  users to securely share temporary secrets with others.
- `crates/bitwarden-ssh/README.md`: Contains the implementation of the ssh generators and import for
  the Bitwarden Password Manager.
- `crates/bitwarden-vault/README.md`: Defines the data model for the vault items both encrypted and
  decrypted. It also handles conversions between the two states by implementing `Encryptable`.

## foundation

- `crates/bitwarden-core/README.md`: Contains core functionality used by the feature crates.
- `crates/bitwarden-crypto/README.md`: Cryptographic primitives and protocols for the Bitwarden SDK,
  including key store for securely working with keys held in memory. The general aspiration is for
  this crate to handle all the difficult cryptographic operations and expose higher level concepts
  to the rest of the SDK.
- `crates/bitwarden-error/README.md`: Provides error macros for simplifying error handling when
  working with WebAssembly.
- `crates/bitwarden-ipc/README.md`: Type-safe IPC framework with pluggable encryption and transport.
- `crates/bitwarden-state/README.md`: Type safe persisted state management for the Bitwarden SDK.
  Provides Repositories and Key-Value (settings) abstractions. Should always be used when dealing
  with persisted state.
- `crates/bitwarden-threading/README.md`: Provides abstractions around threading and async quirks in
  FFI contexts. Allows a single implementation to work across native and WASM targets.
- `crates/bitwarden-uuid/README.md`: UUID utilities and macros for simplifying UUID handling across
  platforms.

## utility

- `crates/bitwarden-cli/README.md`: Common utilities for the Bitwarden Password Manager CLI and
  Secrets Manager CLI. Any code shared between `bw` and `bws` should go here.
- `crates/bitwarden-encoding/README.md`: Base64 and Base64Url abstractions for dealing with Base64
  encoded data. Should always be used when dealing with B64 encoded data over external libraries.
- `crates/bitwarden-test/README.md`: Test utilities such as mock implementations and helpers for
  testing repositories and testing non mockable API bindings (outside of bitwarden-api crates).
- `crates/bitwarden-uniffi-error/README.md`: Provides utilities to convert results inside
  `uniffi::custom_type!` calls, so that they don't produce panics when there is a parsing error.
