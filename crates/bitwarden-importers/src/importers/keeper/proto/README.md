# Generated Keeper Protobuf Modules

This directory contains **generated** Rust code compiled from Protocol Buffer definitions in
`proto/keeper/`. These files are committed to the repository — they are read-only and should not be
edited manually.

## File Organization

Each `.rs` file corresponds to a Keeper protobuf message package:

- `authentication.rs` — Keeper login request/response messages
- `breach_watch.rs` — Breach watch notification messages
- `enterprise.rs` — Enterprise account and user management messages
- `graph_sync.rs` — Graph database sync protocol messages
- `notification_center.rs` — Push notification metadata and structure
- `push.rs` — Push notification message types
- `records.rs` — Vault record and folder definitions (primary importer use)
- `sso_cloud.rs` — Single sign-on cloud integration messages
- `tokens.rs` — Token and credential management messages
- `vault.rs` — Vault sync and data structure messages

## Regenerating from `.proto` Files

When a `.proto` file in `proto/keeper/` is modified, the corresponding generated `.rs` files must be
regenerated using the `prost` compiler. Run `support/build-keeper-proto.sh` from the workspace root
to update these files. The script regenerates the code and applies formatting. Committed generated
files must be kept in sync with their source `.proto` definitions.

## Integration with the Importer

The Keeper importer uses these protobuf messages to:

1. **Parse wire data** — deserialize encrypted export files and API responses
2. **Access record metadata** — type discriminants, timestamps, cryptographic keys
3. **Handle authentication** — decrypt session tokens and derive vault access keys
4. **Support account sync** — process multi-device sync and shared vault updates

See the importer module for the logic that consumes these types.

## Testing

Roundtrip serialization tests live in the `tests/` subdirectory:

- `authentication_tests.rs` — Authentication protocol message tests
- `vault_tests.rs` — Vault record and sync message tests

Run tests with `cargo test -p bitwarden-importers --lib importers::keeper::proto::tests`
