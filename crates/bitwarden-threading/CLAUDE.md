# bitwarden-threading

Read [README.md](./README.md) for architecture overview and consult runnable code in
[examples/](./examples/) (usage demonstrations of the public API) and [tests/](./tests/)
(integration tests showing how components work together) for correct usage patterns.

## Critical Rules

**Native requires LocalSet**: `tokio::task::spawn_local` panics without LocalSet context—WASM does
not have this requirement.

**No blocking operations**: Blocking tasks stalls the entire runner since all tasks execute on a
single thread.
