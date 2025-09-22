# Bitwarden-crypto safe module

The safe module provides high-level cryptographic tools for building secure protocols and features.
When developing new features, use this module first before considering lower-level primitives from
other parts of `bitwarden-crypto`.

## Password-protected key envelope

Use the password protected key envelope to protect a symmetric key with a password. Examples
include:

- locking a vault with a PIN/Password
- protecting exports with a password

Internally, the module uses a KDF to protect against brute-forcing, but it does not expose this to
the consumer. The consumer only provides a password and key.
