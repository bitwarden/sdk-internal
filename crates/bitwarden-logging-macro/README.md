# Bitwarden Logging Macro

Provides a safer wrapper around [`tracing::instrument`] that enforces `skip_all` by default.

By default, `tracing::instrument` records every function argument that implements `Display` or
`Debug` as a span field. In a vault-handling SDK this is a foot-gun: forgetting `skip_all` on a
function like `derive_master_key(password, email, ...)` would log the user's password.

The `#[bitwarden_logging::instrument]` attribute re-emits as
`#[tracing::instrument(skip_all, ...)]`, making field logging opt-in via `fields(...)`.

```rust,ignore
use bitwarden_logging::instrument;

// All args skipped by default.
#[instrument]
fn sensitive(password: &str) { /* ... */ }

// Explicit opt-in.
#[instrument(fields(user_id = ?id))]
fn less_sensitive(id: Uuid, password: &str) { /* ... */ }
```

User-supplied `skip(...)` and `skip_all` are rejected at compile time, since `skip_all` is already
enforced and `fields(...)` is the way to opt in.

## Lint backstop

A companion dylint rule (`tracing_instrument`) catches any use of `tracing::instrument` that slips
past the convention. It identifies the macro by its definition in the `tracing_attributes` crate, so
all of these are caught:

- `#[tracing::instrument]`
- `use tracing::instrument; #[instrument]`
- `use tracing::instrument as foo; #[foo]`

The wrapper opts out of the lint at its own emission site by including
`#[allow(unknown_lints, tracing_instrument)]` next to the `#[tracing::instrument]` it generates, so
the lint can stay general.

The lint currently defaults to `allow` so existing workspace call sites have time to migrate. Crates
that have been swept can opt in with `#![warn(tracing_instrument)]` (or `deny`) at the crate root.
The default will flip to `warn` once the workspace is clean.
