# 1Password access module

Read access to a 1Password account. Logging in needs the username, master password and Secret Key,
plus a TOTP passcode when the account has 2FA. An SSO account needs the username instead, and the
user signs in with the identity provider. Once authenticated it downloads and decrypts every
accessible vault into a native 1Password model.

A Rust port of the OnePassword module in Bitwarden's C# `password-manager-access` library.

The 1P and BW name things differently. 1P has vaults that are independent, could be shared
separately, could have different access rights, encrypted with different keys. The importer turns
each one into a Bitwarden folder. 1P doesn't have folders, only tags.

## Notes

- Supports TOTP 2FA only ATM
- No service account support (they are not so good for export/import)
- Two entry points, `Client::open_account` and `Client::open_account_sso`, and
  `Client::sign_in_methods` to tell which one an account needs. No vault selection, no random access
- Added `aes-gcm`, `hkdf`, `crypto-bigint` and `icu_normalizer` to the workspace, will increase the
  wasm size.
- SRP uses `crypto-bigint` rather than `num-bigint` for the constant-time `modpow`
- The legacy path is transcribed from the client and cannot be tested end to end. Patching the web
  client to mint a `PBES2-HS256` account fails: the server answers `POST /api/v1/user/auth` with a
  400, so no new account can be created on it. `fixtures/master-key-vectors.json` covers the
  derivation for both algorithms instead
- Only the credentials and the keys are zeroed. The decrypted vault data is not
- The replay tests run on an account captured into `fixtures/account`, re-keyed to the fake
  credentials in `replay.rs`. After a recapture, run `node scripts/reencrypt.mjs <keysets|account>`
  from `fixtures` on each response, passing the real account's credentials as `--old-*`

## SSO

- The crypto is pinned by the generated test vectors in `fixtures/sso-vectors.json` and
  `sso/flow_tests.rs` runs the whole login against a fake server
- Every import is a new device with a fresh uuid and nothing is kept between imports, so the user
  approves it on an enrolled device and types the verification code shown there. Then a CPace
  exchange (Ristretto255) hands over the credential bundle, the SRP x and the account unlock key
- Added `curve25519-dalek` to the workspace

## TODO

- The client fingerprint lives in `identity.rs`: app version, HTTP library and per-platform strings.
  Question: do we need per-platform impersonation, or is one fixed identity enough?
- There are many tests converted from the C# repo, they became very noisy in Rust. Do we even need
  them? See start_registers_an_unknown_device_then_retries for an example.
- Do we need to import password history?
- Legacy SRP (`SRP-4096`) is rejected, the client derives it differently and ends in SHA-1
- This module reaches for `hkdf`, `aes-gcm` and `rsa` directly because `bitwarden-crypto` keeps
  those primitives private. Question: should `bitwarden-crypto` expose them, so feature crates do
  not each depend on RustCrypto themselves?
- Decide partial-import policy: import valid data; report missing-access or explicitly unsupported
  data as skipped; should unexpected JSON, decryption or internal failures abort or also be skipped?
- The username goes on the wire raw, `v2/auth/methods` and `v3/auth/start` do not get the normalized
  one
- `OnePasswordError::TwoFactorRequired` is never constructed
- SSO: `taga` is not verified, so the server is trusted to relay an honest device
- SSO: dropping the login future during an enrollment skips `end_enrollment` and the server side
  cancel; only `SsoEnrollmentContext::cancelled()` cleans up
- SSO: no UniFFI bindings for the callbacks yet
