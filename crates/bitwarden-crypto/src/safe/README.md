# Bitwarden-crypto safe module

The safe module provides high-level cryptographic tools for building secure protocols and features.
When developing new features, use this module first before considering lower-level primitives from
other parts of `bitwarden-crypto`.

Usage examples of all safe APIs are provided in the crate's `examples` directory.

## Password-protected key envelope

Use the password protected key envelope to protect a symmetric key with a password. Examples
include:

- locking a vault with a PIN/Password
- protecting exports with a password

Internally, the module uses a KDF to protect against brute-forcing, but it does not expose this to
the consumer. The consumer only provides a password and key.

## Data envelope

Use the data envelope to protect a struct (document) of data. Examples include:

- protecting a vault item
- protecting metadata (name, etc.) of a collection
- protecting a vault report

The serialization of the data and the creation of a content encryption key is handled internally.
Calling the API with a decrypted struct, the content encryption key ID and the encrypted data are
returned.
