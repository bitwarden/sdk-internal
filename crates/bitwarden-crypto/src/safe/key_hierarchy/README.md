# Key Hierarchy

Password manager encryption will organize cryptographic material into a strict hierarchy. This is
currently not strictly upheld, but will be upheld for all future cryptographic modifications, and
migrated towards. Only passwords and high-entropy secrets ever cross the SDK boundary. **Keys never
leave the SDK.** Outside the boundary, a client supplies a low-entropy secret (a PIN or password) or
a high-entropy secret (PRF output, a key-connector secret, a random URL fragment, biometric-derived
bytes) — never key material the SDK is responsible for.

```text
Outside the SDK boundary - only secrets cross it, never keys:

    Password / PIN  (low entropy)
        |  PasswordProtectedKeyEnvelope  (slow, memory-hard KDF)
        |
    High-entropy secret  (PRF, key-connector, URL fragment)
        |  SecretProtectedKeyEnvelope  (cheap KDF)
        v
    +-------------------------------------------------------------+
    | Key Encryption Key (KEK)  --  reused                        |
    +-------------------------------------------------------------+
        |  wraps other keys:
        |    - SymmetricKeyEnvelope           -> a DEK or another KEK
        |    - PrivateKeyEnvelope   (n/i)     -> a private key
        |    - SignatureKeyEnvelope (n/i)     -> a signing key
        v
    +-------------------------------------------------------------+
    | Data Encryption Key (DEK)  --  fresh per data, NEVER reused |
    +-------------------------------------------------------------+
        |  encrypts content:
        |    - DataEnvelope
        |    - AttachmentStream (n/i)
        v
    +-------------------------------------------------------------+
    | Content                                                     |
    +-------------------------------------------------------------+
```

`(n/i)` = not implemented.

**Key encryption keys (KEKs).** A KEK is protected by a
[password-protected key envelope](../README.md#password-protected-key-envelope) or a
[secret-protected key envelope](../README.md#secret-protected-key-envelope). A KEK **only ever
encrypts other keys** — never content directly — via a
[symmetric key envelope](../README.md#symmetric-key-envelope), a private key envelope (not yet
implemented), or a signature key envelope (not yet implemented). One of the keys a KEK wraps (via a
symmetric key envelope) may itself be another KEK, allowing chained key hierarchies. A KEK is
**reused**: the same KEK wraps many keys over its lifetime, and rotating it means re-wrapping only
the keys it protects, not re-encrypting content.

**Data encryption keys (DEKs).** A symmetric key envelope may hold a DEK. A DEK encrypts content —
via a [data envelope](../README.md#data-envelope) or an attachment stream (not yet implemented).
Unlike a KEK, a DEK is **freshly generated together with the data it protects and is _never_
reused**. This makes key rotation cheap: to rotate the wrapping key, only the (small) wrapped DEKs
need re-uploading rather than all content.

**Safe Internal Keys.** A safe primitive may use an internally derived key. For instance, the
[password-protected key envelope](../README.md#password-protected-key-envelope) and
[secret-protected key envelope](../README.md#secret-protected-key-envelope) each derive a key
internally. These are neither DEKs nor KEKs but internal to the constructions and not considered in
this hierarchy.

## Example: vault encryption

A user's vault maps onto the hierarchy as follows. The user's low-entropy secret (their master
password or a PIN) protects the **user key**, which is a KEK. That user key wraps the account's
asymmetric private key, its signing key, and the content-encryption-key of every vault item.

Each vault item's content-encryption-key (its "cipher key") is **itself a KEK**: it does not encrypt
content directly. Instead it wraps that item's DEKs — one DEK per attachment, plus the single data
envelope key that protects the item's own fields. The attachment keys and the data envelope key are
DEKs, and they are what actually encrypt content.

```text
    Password / PIN
        |  PasswordProtectedKeyEnvelope
        v
    +-------------------------------------------------------------+
    | User Key  (KEK)                                             |
    +-------------------------------------------------------------+
        |  wraps, via SymmetricKeyEnvelope / PrivateKeyEnvelope /
        |  SignatureKeyEnvelope:
        |
        +--> Private key
        +--> Signing key
        +--> Cipher key #1 .. #N   (each is itself a KEK)
                |  each cipher key wraps, via SymmetricKeyEnvelope:
                |
                +--> Attachment key #1 .. #M  (DEK) --> AttachmentStream
                +--> Data envelope key (DEK, single) --> DataEnvelope
```

## Example: send encryption (mock design)

> This is a mock design used to illustrate the hierarchy; it does not necessarily reflect the
> current send implementation, but is a way to implement the send feature based on the send
> primitives.

A send is unlocked with its **send secret** — a high-entropy secret carried in the share URL
fragment. Because it is high-entropy, it maps to the **send key** through a secret-protected key
envelope (cheap KDF) rather than a password-protected one.

The send key is a KEK. It wraps the send's DEKs: the single data envelope key that protects the
send's text/fields, and one attachment key per file. As always, the DEKs — not the KEK — encrypt the
content.

```text
    Send secret  (high-entropy, share-URL fragment)
        |  SecretProtectedKeyEnvelope
        v
    +-------------------------------------------------------------+
    | Send Key  (KEK)                                             |
    +-------------------------------------------------------------+
        |  wraps, via SymmetricKeyEnvelope:
        |
        +--> Data envelope key (DEK, single) --> DataEnvelope
        +--> Attachment key #1 .. #M  (DEK)    --> AttachmentStream
```
