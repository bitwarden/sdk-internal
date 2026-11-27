# Bitwarden Crypto Primitives

Single home for the raw cryptographic primitives used by the SDK. Every other crate calls these
wrappers instead of a crypto library directly, so the implementing backend can be swapped in one
place.

```text
 bitwarden-crypto, importers, vault, ...
                │
                ▼
 bitwarden-crypto-primitives  (stable API: aes_gcm, rsa, ed25519, ...)
                │
                ▼
          backend driver       (RustCrypto)
```

Prefer the higher level `bitwarden-crypto` APIs. This crate is hazmat: it does not manage nonces,
key lifecycles, or protocol composition.
