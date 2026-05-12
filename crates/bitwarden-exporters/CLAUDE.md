# bitwarden-exporters

Read any available documentation: [README.md](./README.md) for architecture and
[resources/](./resources/) for test fixtures.

## Critical Rules

**Export types are separate from vault types**: `Cipher`, `Folder`, and `ImportingCipher` in this
crate are intentionally duplicated from `bitwarden-vault` to maintain a stable export API. Do not
replace them with vault types directly.

**CSV only supports Login and SecureNote**: Cards, identities, and SSH keys are silently skipped
during CSV export. This is intentional — the format cannot represent them.

**Encrypted JSON uses account KDF settings**: The password-protected export derives its encryption
key using the user's configured KDF (PBKDF2 or Argon2id). The `Client` must have KDF parameters
available or the export will fail.

**CXF import must manually encrypt fido2 credentials**: When importing CXF payloads containing
passkeys, the import path calls `set_new_fido2_credentials` to encrypt them via the
`KeyStoreContext` before returning. Do not skip this step.
