# Architecture Documentation

The internal SDK is structured as a single Git repository with multiple internal crates. This
document describes the general structure of the project. Please review the individual `README`s in
the repository for information about the specific crates or implementation details.

We generally strive towards extracting features into separate crates to keep the `bitwarden-core`
crate as lean as possible. This has multiple benefits such as faster compile-time and clear
ownership of features.

> This document was auto-generated and should not be edited directly.

## API bindings

API bindings for Bitwarden server services. Can be either auto generated or hand-written. These
crates should only contain server bindings and no business logic.

- `crates/bitwarden-api-api/README.md`: Auto-generated OpenAPI bindings for bitwarden-api-api (**DO
  NOT edit - regenerate from OpenAPI specs**)
- `crates/bitwarden-api-identity/README.md`: Auto-generated OpenAPI bindings for
  bitwarden-api-identity (**DO NOT edit - regenerate from OpenAPI specs**)
- `crates/bitwarden-api-key-connector/README.md`: Manually-maintained API client bindings for the
  Bitwarden Key Connector service exposing UserKeysApi for retrieving and managing user encryption
  keys in enterprise environments.

## Core and Utilities

Foundational modules and helpers.

- `crates/bitwarden-cli/README.md`: Provides shared CLI utilities including terminal color
  configuration, color_eyre error formatting, and interactive text prompts for the `bw` Password
  Manager CLI and `bws` Secrets Manager CLI.
- `crates/bitwarden-core/README.md`: Contains core functionality used by the feature crates.
- `crates/bitwarden-crypto/README.md`: Cryptographic primitives and protocols for the Bitwarden SDK,
  including key store for securely working with keys held in memory. The general aspiration is for
  this crate to handle all the difficult cryptographic operations and expose higher level concepts
  to the rest of the SDK.
- `crates/bitwarden-encoding/README.md`: Base64 and Base64Url abstractions for dealing with Base64
  encoded data. Should always be used when dealing with B64 encoded data over external libraries.
- `crates/bitwarden-error/README.md`: Provides error macros for simplifying error handling when
  working with WebAssembly.
- `crates/bitwarden-ipc/README.md`: Type-safe inter-process communication framework enabling
  request-response messaging with pluggable encryption, session management, and transport backends
  through a unified `IpcClient` interface for native and WASM targets.
- `crates/bitwarden-state/README.md`: Type-safe persisted state management providing client-managed
  repositories (application-supplied storage) and SDK-managed repositories (SQLite/IndexedDB
  backends) with automatic type registration via the `register_repository_item!` macro.
- `crates/bitwarden-test/README.md`: Test utilities such as mock implementations and helpers for
  testing repositories and testing non mockable API bindings (outside of bitwarden-api crates).
- `crates/bitwarden-threading/README.md`: Provides abstractions around threading and async quirks in
  FFI contexts. Allows a single implementation to work across native and WASM targets.
- `crates/bitwarden-uniffi-error/README.md`: Provides utilities to convert results inside
  `uniffi::custom_type!` calls, so that they don't produce panics when there is a parsing error.
- `crates/bitwarden-uuid/README.md`: UUID utilities and macros for simplifying UUID handling across
  platforms.

## Features

Core business logic split into separate feature oriented crates. When adding new functionality it
should be added to an existing feature crate or a new feature crate should be created.

- `bitwarden_license/bitwarden-sm/README.md`: Bitwarden Secrets Manager
- `crates/bitwarden-auth/README.md`: Authentication functionality including identity token
  management, user registration with account cryptography initialization (SSO, master password, TDE,
  key-connector flows), and send access token requests for password/email-protected sends.
- `crates/bitwarden-collections/README.md`: Defines the data model for collections both encrypted
  and decrypted. It also handles conversions between those two states by implementing `Encryptable`.
  It also provides `Tree` struct which allows all structs implementing `TreeItem` to be represented
  in a tree structure along with functions to access each node.
- `crates/bitwarden-exporters/README.md`: Vault data export/import in multiple formats (CSV, JSON,
  password-encrypted JSON) with support for Apple's Credential Exchange Format (CXF) for credential
  transfer between Bitwarden and native iOS applications.
- `crates/bitwarden-fido/README.md`: FIDO2 (Passkey) implementation for Bitwarden Password Manager.
- `crates/bitwarden-generators/README.md`: Various generators implementations for the Bitwarden
  Password Manager. Such as password, passphrase and username generation.
- `crates/bitwarden-policies/README.md`: Admin console owned policy code.
- `crates/bitwarden-send/README.md`: All Bitwarden Send related domain logic. Bitwarden Send allows
  users to securely share temporary secrets with others.
- `crates/bitwarden-ssh/README.md`: Contains the implementation of the ssh generators and import for
  the Bitwarden Password Manager.
- `crates/bitwarden-vault/README.md`: Comprehensive encrypted/decrypted data models and
  cryptographic operations for vault items including ciphers (logins, secure notes, cards,
  identities, SSH keys), folders, TOTP generation, attachments, and password risk evaluation through
  the `VaultClient` API.

## Application Interfaces

An application interface collects the various features relevant for a given Bitwarden product, e.g.
Password Manager, or Secrets Manager, into a single easy-to-use crate for that particular product.

- `crates/bitwarden-pm/README.md`: Unified application interface aggregating sub-clients to serve as
  a single entry point for Password Manager applications.
- `crates/bw/README.md`: Work-in-progress Rust CLI for Bitwarden Password Manager providing
  command-line access to authentication, vault operations, password generation, imports/exports, and
  admin functions with multiple output formats.

## Language bindings

Language bindings target `wasm`, `iOS`, and `Android`. The two mobile targets are built using
UniFFI.

- `crates/bitwarden-uniffi/README.md`: Mobile bindings for iOS (swift) and Android (kotlin) which
  exposes the Bitwarden Password Manager to our mobile applications using UniFFI.
- `crates/bitwarden-wasm-internal/README.md`: WebAssembly bindings for the Bitwarden SDK, consumed
  by the internal Bitwarden web clients. Thin bindings only - no business logic.
