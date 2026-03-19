# Bitwarden Exporters

Contains the export and import functionality for Bitwarden Password Manager.

## Supported formats

| Format              | Export | Import | Source                  |
| ------------------- | ------ | ------ | ----------------------- |
| CSV                 | Yes    | No     | `src/csv.rs`            |
| JSON                | Yes    | No     | `src/json.rs`           |
| Encrypted JSON      | Yes    | No     | `src/encrypted_json.rs` |
| Credential Exchange | Yes    | Yes    | `src/cxf/`              |

- **CSV** — Flat export of Login and SecureNote items only. Cards, identities, and SSH keys are
  excluded.
- **JSON** — Unencrypted JSON containing all cipher types (Login, SecureNote, Card, Identity,
  SshKey) and folders.
- **Encrypted JSON** — Same structure as JSON, but password-protected using the account's KDF
  settings (PBKDF2 or Argon2id).
- **CXF (Credential Exchange Format)** — [FIDO Alliance standard][cxf-spec] for transferring
  credentials between providers. This is the only format that supports both export and import.

[cxf-spec]: https://fidoalliance.org/specifications-credential-exchange-specifications/

## Crate structure

```text
src/
├── lib.rs                 # Public types and re-exports
├── exporter_client.rs     # ExporterClient + ExporterClientExt trait (entry point)
├── export.rs              # Orchestrates decrypt → format → output
├── models.rs              # Conversions between vault models and export types
├── error.rs               # ExportError (aggregates per-format errors)
├── csv.rs                 # CSV formatter
├── json.rs                # JSON formatter
├── encrypted_json.rs      # Password-protected JSON formatter
├── uniffi_support.rs      # UniFFI mobile bindings support
└── cxf/                   # Credential Exchange Format
    ├── mod.rs
    ├── export.rs          # build_cxf()
    ├── import.rs          # parse_cxf()
    └── *.rs               # Per-credential-type converters (login, card, identity, etc.)
```

## Data flow

### Export (CSV & JSON)

[`ExporterClient::export_vault`] decrypts ciphers and folders via the `KeyStore`, passes them
through the chosen format module (`csv`, `json`, or `encrypted_json`), and returns the result as a
`String`.

```rust,no_run
use bitwarden_core::Client;
use bitwarden_exporters::{ExporterClientExt, ExportFormat};
# use bitwarden_vault::{Cipher, Folder};

fn export(client: &Client, folders: Vec<Folder>, ciphers: Vec<Cipher>) {
    let export = client
        .exporters()
        .export_vault(folders, ciphers, ExportFormat::Json)
        .unwrap();
}
```

### Credential Exchange

#### Import

[`ExporterClient::import_cxf`] parses a CXF JSON string into [`ImportingCipher`] values, encrypts
each one via the `KeyStore`, and returns `Vec<Cipher>` ready for storage.

```rust,no_run
use bitwarden_core::Client;
use bitwarden_exporters::ExporterClientExt;

fn import(client: &Client, cxf_payload: String) {
    let ciphers = client
        .exporters()
        .import_cxf(cxf_payload)
        .unwrap();
}
```

#### Export

[`ExporterClient::export_cxf`] decrypts ciphers and converts them to the [Credential Exchange
Format][cxf-spec].

```rust,no_run
use bitwarden_core::Client;
use bitwarden_exporters::{Account, ExporterClientExt};
# use bitwarden_vault::Cipher;

fn export_cxf(client: &Client, account: Account, ciphers: Vec<Cipher>) {
    let cxf_json = client
        .exporters()
        .export_cxf(account, ciphers)
        .unwrap();
}
```

## Testing

Run the crate tests with:

```sh
cargo test -p bitwarden-exporters
```

Test fixtures live in the `resources/` directory (sample JSON exports, CXF payloads from Dashlane,
1Password, and Devolutions).
