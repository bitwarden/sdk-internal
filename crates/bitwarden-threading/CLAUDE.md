# bitwarden-threading

Read any available documentation: [README.md](./README.md) for architecture,
[examples/](./examples/) for usage patterns, and [tests/](./tests/) for integration tests.

## Critical Rules

**Native requires LocalSet**: `tokio::task::spawn_local` panics without LocalSet context—WASM does
not have this requirement.

**No blocking operations**: Blocking tasks stalls the entire runner since all tasks execute on a
single thread.
