# bitwarden-importers

Internal crate implementing format-specific vault importers for the Bitwarden SDK. Do not use
directly.

Exposes `client.importers()` ([`ImporterClient`]) with:

- `import_kdbx` — parses a KeePass KDBX (`.kdbx`) database (3.1 + 4, via the `keepass` crate),
  encrypts the entries for the user's personal vault or a given organization, and submits them to
  the server's import endpoint. Returns per-type counts.

## Architecture

The shared "interchange" model (`ImportingCipher`, `CipherType`, `Login`/`Card`/…, and the
`From<ImportingCipher> for CipherView` bridge plus `encrypt_import`) lives in `bitwarden-exporters`
and is reused here — this crate depends on `bitwarden-exporters`. CXF import remains in
`bitwarden-exporters` because it is one half of a bidirectional codec.
