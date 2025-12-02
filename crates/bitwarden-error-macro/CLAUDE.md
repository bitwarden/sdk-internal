# bitwarden-error-macro

Read any available documentation: [README.md](./README.md) for architecture,
[examples/](./examples/) for usage patterns, and [tests/](./tests/) for integration tests.

## Three Modes

Specified via `#[bitwarden_error(mode)]`:

- **basic**: String errors only—converts to JS string via `ToString`
- **flat**: Variant-based—generates `FlatError` trait, TypeScript union types
- **full**: Structure-based—uses `Serialize` + `tsify` for full error details

Generates platform-specific bindings: `From<T> for JsValue` (WASM), TypeScript interfaces,
`uniffi::Error` (mobile).

## Critical Rules

**Requires `thiserror`**: All error enums must derive `#[derive(Error)]` from thiserror crate.

**Conditional generation**: WASM bindings only generated when `wasm` feature enabled—check with
`cfg!(feature = "wasm")`.

**Unsupported**: `full` mode with `export_as` parameter is not supported.

**Debug with `cargo expand`**: If macro output is unclear, use `cargo expand` to inspect generated
code.
