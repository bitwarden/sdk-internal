# Bitwarden Autotype

Provides encrypted IPC channels for use with the Bitwarden Desktop Autotype GA implementation, using
[`bitwarden_ipc`].

The crate is WASM-only (everything lives behind the `wasm` feature and is re-exported from
`@bitwarden/sdk-internal`). It has no Autotype logic of its own; it contains the typed,
Noise-encrypted channels for use between the two desktop processes.

## Channels

| Request                              | Direction     | Payload                   | Response                                   |
| ------------------------------------ | ------------- | ------------------------- | ------------------------------------------ |
| `AutotypeSetEnabledRequest`          | render → main | `enabled: bool`           | `{ success: bool }`                        |
| `AutotypeSetKeyboardShortcutRequest` | render → main | `shortcut: Vec<String>`   | `{ success: bool }`                        |
| `AutotypeListRunningAppsRequest`     | render → main | _(none)_                  | `{ apps: AutotypeRunningApp[] }`           |
| `AutotypeGetCredentialsRequest`      | main → render | `app: AutotypeRunningApp` | `{ credentials?: { username, password } }` |

Each process registers the handlers for the requests it receives, backed by its own driver:

- **Main** implements `AutotypeDriver` and calls `registerAutotypeHandlers`. These handlers only
  accept requests from the desktop render process.
- **Render** implements `AutotypeRenderDriver` and calls `registerAutotypeRenderHandlers`. These
  handlers only accept requests from the desktop main process.

## Tests

Coverage lives in the TypeScript integration tests under
`crates/bitwarden-wasm-internal/integration-tests/tests/autotype/`, which test the
`serialize → encrypt → decrypt → deserialize` path over a paired in-memory transport.

Run the tests with `npm run build:test` from `crates/bitwarden-wasm-internal/integration-tests`.
