# Bitwarden Autotype

Provides encrypted IPC channels for use with the Bitwarden Desktop Autotype GA implementation, using
[`bitwarden_ipc`].

The crate is WASM-only (everything lives behind the `wasm` feature and is re-exported from
`@bitwarden/sdk-internal`). It has no Autotype logic of its own; it contains the typed,
Noise-encrypted channels for use between the two desktop processes.

## Channels

| Request                                             | Direction       | Payload                 | Response                         |
| --------------------------------------------------- | --------------- | ----------------------- | -------------------------------- |
| `AutotypeSetEnabledRequest`                         | renderer → main | `enabled: bool`         | `{ success: bool }`              |
| `AutotypeSetKeyboardShortcutRequest`                | renderer → main | `shortcut: Vec<String>` | `{ success: bool }`              |
| `AutotypeListRunningAppsRequest`                    | renderer → main | _(none)_                | `{ apps: AutotypeRunningApp[] }` |
| `AutotypeSetConfirmationEnabledFromRendererRequest` | renderer → main | `enabled: bool`         | `{ success: bool }`              |
| `AutotypeSetConfirmationEnabledFromMainRequest`     | main → renderer | `enabled: bool`         | `{ success: bool }`              |

Each process registers the handlers for the requests it receives, backed by its own driver:

- **Main** implements `AutotypeMainDriver` and calls `registerAutotypeMainHandlers`. These handlers
  only accept requests from the desktop renderer.
- **Renderer** implements `AutotypeRenderDriver` and calls `registerAutotypeRenderHandlers`. These
  handlers only accept requests from the desktop main process.

## Tests

Coverage lives in the TypeScript integration tests under
`crates/bitwarden-wasm-internal/integration-tests/tests/autotype/`, which test the
`serialize → encrypt → decrypt → deserialize` path over a paired in-memory transport.

Run the tests with `npm run build:test` from `crates/bitwarden-wasm-internal/integration-tests`.
