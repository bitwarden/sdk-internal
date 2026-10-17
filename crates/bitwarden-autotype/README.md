# Bitwarden Autotype

Provides encrypted IPC channels for use with the Bitwarden Desktop Autotype GA implementation, using
[`bitwarden_ipc`] within sdk-internal.

The crate is WASM-only — everything lives behind the `wasm` feature and is re-exported from
`@bitwarden/sdk-internal`. It holds no Autotype logic of its own; it is the typed, Noise-encrypted
wire between the two desktop processes.

## Who does what

Autotype is owned by the **desktop main process**, which holds the global keyboard shortcut and the
platform implementation. The **renderer** drives it but cannot reach it directly.

- Main calls `autotypeRegisterHandlers(ipcClient, driver)` once, handing over a JavaScript object
  implementing the `AutotypeDriver` interface. One `ThreadBoundRunner` is shared across all
  handlers, so every channel reaches the same driver instance.
- The renderer calls the `autotypeRequest*` functions, each of which sends to
  `Endpoint::DesktopMain` and resolves with the matching response. They reject only when the request
  could not be delivered or answered — main unreachable, the request timed out, or no handler
  registered. A driver that fails on main still resolves; see
  [Failure semantics](#failure-semantics).

## Channels

| Request                              | Payload                 | Response                         |
| ------------------------------------ | ----------------------- | -------------------------------- |
| `AutotypeSetEnabledRequest`          | `enabled: bool`         | `{ success: bool }`              |
| `AutotypeSetKeyboardShortcutRequest` | `shortcut: Vec<String>` | `{ success: bool }`              |
| `AutotypeListRunningAppsRequest`     | _(none)_                | `{ apps: AutotypeRunningApp[] }` |

`shortcut` is carried through unvalidated — modifiers first, base key last. What counts as a usable
combination is the receiving client's call, not the SDK's.

## Failure semantics

The driver is platform code that may be unavailable, so no channel propagates an error to the
renderer. Every failure is logged through `tracing` and folded into a benign value:

- **Boolean channels** report `success: false` when the driver throws, returns a non-boolean, or
  cannot be reached. `true` only ever means the driver said the change was applied.
- **`list_running_apps`** deserializes entry by entry and skips what it cannot read, so one
  unreadable process does not cost the caller the rest of the list. A driver that throws, cannot be
  reached, or resolves with anything that is not an array yields an empty list.

One consequence is worth designing around on the renderer side: an empty `apps` list means either
that nothing was found or that enumeration failed. The two are not distinguished.

## Tests

Coverage lives in the TypeScript integration tests under
`crates/bitwarden-wasm-internal/integration-tests/tests/autotype/`, which exercise the real
serialize → encrypt → decrypt → deserialize path over a paired in-memory transport. Run them with
`npm run build:test` from `crates/bitwarden-wasm-internal/integration-tests`.
