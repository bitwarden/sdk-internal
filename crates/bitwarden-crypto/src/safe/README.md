# Bitwarden-crypto safe module

The safe module provides high-level cryptographic tools for building secure protocols and features. When developing new features, use this module first before considering lower-level primitives from other parts of `bitwarden-crypto`.

## Password-protected key envelope

The password protected key envelope should be used, when the goal is to protect a symmetric key with
a password, for example for locking a vault with a PIN/Password, for protecting exports with a
password, etc. Internally, a KDF is used to protect against brute-forcing, but this is not exposed
to the consumer. The consumer only provides a password and key.
