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
- OpenSSL: `RUSTFLAGS='--cfg bitwarden_crypto_backend="openssl"' cargo build`. Builds a vendored
  OpenSSL 3.x; set `OPENSSL_NO_VENDOR=1` to link a system OpenSSL ≥ 3.5 (ML-DSA, Argon2id,
  seed-based keys) instead. Not available on wasm32. Two primitives still come from RustCrypto,
  since OpenSSL lacks them: `xchacha20_poly1305` (no HChaCha20) and `ristretto255` (no group API).

Prefer the higher level `bitwarden-crypto` APIs. This crate is hazmat: it does not manage nonces,
key lifecycles, or protocol composition.
