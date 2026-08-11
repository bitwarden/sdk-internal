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
