# Generated Keeper Protobuf Modules

This directory contains **generated** Rust code compiled from Protocol Buffer definitions in
`proto/keeper/`. These files are committed to the repository — they are read-only and should not be
edited manually.

## File Organization

Each `.rs` file is generated from a corresponding Keeper protobuf source file. Modules are named
after their proto package names (not file names):

- `authentication.rs` (from `api-request.proto`) — Keeper login request/response messages
- `breach_watch.rs` (from `breachwatch.proto`) — Breach watch notification messages
- `enterprise.rs` (from `enterprise.proto`) — Enterprise account and user management messages
- `graph_sync.rs` (from `graph-sync.proto`) — Graph database sync protocol messages
- `notification_center.rs` (from `notification-center.proto`) — Push notification metadata and
  structure
- `push.rs` (from `push.proto`) — Push notification message types
- `records.rs` (from `record.proto`) — Vault record and folder definitions (primary importer use)
- `sso_cloud.rs` (from `ssocloud.proto`) — Single sign-on cloud integration messages
- `tokens.rs` (from `client.proto`) — Breach watch and password breach detection messages
- `vault.rs` (from `sync-down.proto`) — Vault sync and data structure messages

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
