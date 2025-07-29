# Bitwarden-crypto safe module

The safe module contains a high-level set of tools used in building protocols and features involving
cryptography. Whenever possible, a feature should be build with features from this module, before
opting to build with any other, more lower-level primitives in the `bitwarden-crypto` crate.

## Password-protected key envelope

The password protected key envelope should be used, when the goal is to protect a symmetric key with
a password, for example for locking a vault with a PIN/Password, for protecting exports with a
password, etc. Internally, a KDF is used to protect against brute-forcing, but this is not exposed
to the consumer. The consumer only provides a password and key.
