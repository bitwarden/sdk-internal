# 1Password access module

Read access to a 1Password account. Logging in needs the username, master password and Secret Key,
plus a TOTP passcode when the account has 2FA. Once authenticated it downloads and decrypts every
accessible vault into a native 1Password model.

A Rust port of the OnePassword module in Bitwarden's C# `password-manager-access` library.

The 1P and BW name things differently. 1P has vaults that are independent, could be shared
separately, could have different access rights, encrypted with different keys. They will be imported
into Bitwarden collections. 1P doesn't have folders, only tags.

## Notes

- Supports TOTP 2FA only ATM
- No SSO support
- No service account support (they are not so good for export/import)
- One entry point, `Client::download_all_vaults`. No vault selection, no random access
- Added `aes-gcm`, `hkdf`, `pbkdf2`, `crypto-bigint` and `icu_normalizer` to the workspace, will
  increase the wasm size
- SRP uses `crypto-bigint` rather than `num-bigint` for the constant-time `modpow`
- Uses RustCrypto directly rather than `bitwarden-crypto`, which keeps HKDF, AES-GCM and RSA-OAEP
  private. Now that only PBKDF2-SHA256 is supported, `bitwarden_crypto::pbkdf2` would do for that
  one step
- Only the two algorithms the web client implements, `PBES2g-HS256` and the legacy `PBES2-HS256`.
  The `HS512` spellings the C# original accepts are rejected: the client throws `Invalid PBKDF2 alg`
  on them, so its behaviour there is unknown
- The legacy path is transcribed from the client and cannot be tested end to end. Patching the web
  client to mint a `PBES2-HS256` account fails: the server answers `POST /api/v1/user/auth` with a
  400, so no new account can be created on it
- The client fingerprint lives in `identity.rs`: app version, HTTP library and per-platform strings.
  Question: do we need per-platform impersonation, or is one fixed identity enough?
- There are many tests converted from the C# repo, they became very noisy in Rust. Do we even need
  them? See start_registers_an_unknown_device_then_retries for an example.
- Do we need to import password history?
- Only the credentials and the keys are zeroed. The decrypted vault data is not
- The server is never authenticated, `verify_key` does not recompute `serverVerifyHash`
- A wrong password reports as
  `Internal("unexpected response from 'v2/auth/confirm-key' (HTTP 401)")` rather than
  `BadCredentials`. The server only rejects at `confirm-key`, and its body there is not the
  `errorCode` shape `parse_server_error` understands
- The wire DTOs derive `Debug`, so a debug log of one would print secrets
- The sign-in domain is taken as a raw string and never validated
- A vault we hold no key for is skipped silently, and one undecryptable item aborts the whole import
- The module is under a blanket `allow(dead_code, unused_imports)` until the conversion layer lands
- Only the item DTOs in `wire` are public; the auth and session ones are `pub(super)`
