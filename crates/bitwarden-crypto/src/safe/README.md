# Bitwarden-crypto safe module

The safe module provides high-level cryptographic tools for building secure protocols and features.
When developing new features, use this module first before considering lower-level primitives from
other parts of `bitwarden-crypto`.

Usage examples of all safe APIs are provided in the crate's `examples` directory.

## Key Hierarchy

The safe module organizes cryptographic material into a strict hierarchy: which secrets cross the
SDK boundary, how key-encryption-keys (KEKs) and content-encryption-keys (CEKs) relate, and worked
examples for vault and send encryption. See [`key_hierarchy/README.md`](./key_hierarchy/README.md)
for the full description and diagrams.

## Password-protected key envelope

Use the password protected key envelope to protect a symmetric key with a password. Examples
include:

- locking a vault with a PIN/Password
- protecting exports with a password

Internally, the module uses a KDF to protect against brute-forcing, but it does not expose this to
the consumer. The consumer only provides a password and key.

## Secret-protected key envelope

Use the secret-protected key envelope to protect a symmetric key with a **high-entropy** secret of
arbitrary length. Examples include:

- protecting a send's key with a random URL-fragment secret
- protecting a key with PRF output
- protecting a key with a key-connector-stored-secret
- protecting a key with a biometric-derived-secret

Because the secret is assumed to be high-entropy and not brute-forceable, this envelope uses a cheap
KDF (HKDF) rather than the slow, memory-hard KDF used by the password-protected key envelope. The
consumer only provides a secret and a key; the salt is stored in the envelope.

Use the [password-protected key envelope](#password-protected-key-envelope) instead when the secret
is low-entropy (a PIN or password).

## Symmetric key envelope

Use the symmetric key envelope to protect one symmetric key with another symmetric key. The wrapping
key is a [key encryption key (KEK)](#key-hierarchy); the wrapped key is typically a content
encryption key (CEK).

## Data envelope

Use the data envelope to protect a struct (document) of data. Examples include:

- protecting a vault item
- protecting metadata (name, etc.) of a collection
- protecting a vault report

The serialization of the data and the creation of a content encryption key is handled internally.
Calling the API with a decrypted struct, the content encryption key ID and the encrypted data are
returned.

## Guidelines for developers

When adding a new primitive there are a few considerations to make:

- Does this serve a new purpose that is not already fulfilled better otherwise
  - Replacing insecure functionality is a valid reason here
- Is it easy to use for developers that are not cryptography experts
- Does the API prevent (accidental) mis-use by developers that are not cryptography experts
  - Avoid exposing many settings/configurations to API consumers
- Is the format extensible and cover the use-case adequately
- Does the new object have adequate security analysis performed?
- Do we have cryptographic modularity?
  - That is, can we switch to new primitives / algorithms easily?

Further, each new object should be validated against existing known attack classes.

### Namespaces

An important one here is covered by namespacing. When items are signed / encrypted under the same
key, these may be swapped. If the context or type of these objects is different, the consuming code
may misinterpret these, leading to security vulnerabilities. Analysis here is complex. Therefore, a
simpler approach is strong cryptographic namespace separation, which prevents this by adding
metadata about where an object appropriately can be used.

The namespace partitioning happens in two layers, the object layer and the content layer. The
authenticated data of each safe object contains a object namespace key value pair, which allows the
decrypting code to correctly identify whether an object that is being decrypted is actually the
correct object type (e.g. a DataEnvelope). For each object type, there is then another layer of
partitioning, since these objects can be used in many places. For instance, a DataEnvelope may have
the partitioning vault item, account settings, and so on. This content namespace is also stored in
the authenticated data of the safe object.
