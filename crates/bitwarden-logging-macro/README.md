# Bitwarden Logging Macro

Provides a safer wrapper around [`tracing::instrument`] that enforces `skip_all` by default.

By default, `tracing::instrument` records every function argument that implements `Display` or
`Debug` as a span field. In a vault-handling SDK this is a foot-gun: forgetting `skip_all` on a
function like `derive_master_key(password, email, ...)` would log the user's password.

The `#[bitwarden_logging::instrument]` attribute re-emits as `#[tracing::instrument(skip_all, ...)]`,
making field logging opt-in via `fields(...)`.

```rust,ignore
// All args skipped by default.
#[bitwarden_logging::instrument]
fn sensitive(password: &str) { /* ... */ }

// Explicit opt-in.
#[bitwarden_logging::instrument(fields(user_id = ?id))]
fn less_sensitive(id: Uuid, password: &str) { /* ... */ }
```

## Convention: always fully qualify

Always write `#[bitwarden_logging::instrument]` in full. Do **not** write `use
bitwarden_logging::instrument;` followed by a bare `#[instrument]`, because that form is
indistinguishable from `use tracing::instrument;` at the call site — which is exactly the
foot-gun this crate exists to eliminate. The `tracing_instrument` dylint enforces this by
warning on both `#[tracing::instrument]` and bare `#[instrument]`.

User-supplied `skip(...)` and `skip_all` are rejected at compile time, since `skip_all` is
already enforced and `fields(...)` is the way to opt in.
