# Bitwarden Autotype

Provides encrypted IPC channels for use with the Bitwarden Desktop Autotype GA implementation, using
[`bitwarden_ipc`].

The crate is WASM-only (everything lives behind the `wasm` feature and is re-exported from
`@bitwarden/sdk-internal`). It has no Autotype logic of its own; it contains the typed,
Noise-encrypted channels for use between the two desktop processes.

## Channels

| Request                              | Payload                 | Response                         |
| ------------------------------------ | ----------------------- | -------------------------------- |
| `AutotypeSetEnabledRequest`          | `enabled: bool`         | `{ success: bool }`              |
| `AutotypeSetKeyboardShortcutRequest` | `shortcut: Vec<String>` | `{ success: bool }`              |
| `AutotypeListRunningAppsRequest`     | _(none)_                | `{ apps: AutotypeRunningApp[] }` |

## Tests

Coverage lives in the TypeScript integration tests under
`crates/bitwarden-wasm-internal/integration-tests/tests/autotype/`, which test the
`serialize → encrypt → decrypt → deserialize` path over a paired in-memory transport.

Run the tests with `npm run build:test` from `crates/bitwarden-wasm-internal/integration-tests`.
