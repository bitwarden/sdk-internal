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
          backend driver       (RustCrypto | OpenSSL)
```

## Backends

The backend is chosen at compile time with the `bitwarden_crypto_backend` cfg. It is a cfg rather
than a cargo feature so `--all-features` builds keep testing the shipped backend.

- RustCrypto (default): pure Rust. The only backend on wasm32.
- OpenSSL: `RUSTFLAGS='--cfg bitwarden_crypto_backend="openssl"' cargo build`. Links the system
  OpenSSL, which must be ≥ 3.5 (ML-DSA, Argon2id, seed-based keys). Not available on wasm32.
  `xchacha20_poly1305`, `p256` and `ristretto255` are deliberately not supported and panic with
  `unimplemented!`.

Prefer the higher level `bitwarden-crypto` APIs. This crate is hazmat: it does not manage nonces,
key lifecycles, or protocol composition.
