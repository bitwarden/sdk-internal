# bitwarden-importers

Read [README.md](./README.md) for architecture.

## Critical Rules

**Shared model lives in `bitwarden-exporters`**: `ImportingCipher`, `CipherType`, the
`From<ImportingCipher> for CipherView` bridge, and `encrypt_import` are defined in
`bitwarden-exporters` and reused here. Do not duplicate them — depend on `bitwarden-exporters`.

**KDBX maps every entry to a Login**: KeePass entries have no per-type distinction; notes/OTP/extra
fields become sub-fields of a Login cipher. The per-type result counts reflect this.

**Submission encrypts for the destination**: setting `organization_id` on the `CipherView` makes
`key_identifier()` select the org key; org imports also map the target collection. Inputs over 10
MiB are rejected (`KdbxFileTooLarge`).

**Keeper crypto is competitor hazmat, kept out of `bitwarden-crypto`**: `keeper::crypto` ports
Keeper's wire formats (unauthenticated AES-CBC, AES-GCM with prepended nonce, RSA PKCS#1 v1.5,
ECDH-P256 → SHA-256 → AES-GCM, the custom `encryptionParams` blob). It must stay byte-for-byte
compatible with Keeper — do not change the formats. Reuse `bitwarden_crypto` only where the
primitive is standard (PBKDF2); use RustCrypto otherwise. `KeeperCryptoClient` (WASM + UniFFI) only
ever generates random AES-GCM nonces — never expose a caller-supplied nonce.
