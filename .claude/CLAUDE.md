# Bitwarden Internal SDK

Bitwarden's internal cross-platform SDK: core business logic in Rust (edition 2024), consumed by web
and desktop clients through WASM bindings and by mobile through UniFFI. Not for public use — the API
is unstable and changes without warning. Two license zones: `crates/` (OSS) and `bitwarden_license/`
(commercial: `bitwarden-sm`, `bitwarden-commercial-vault`).

Path-scoped rules live in `.claude/rules/` and load automatically when you touch matching files
(crypto crates, generated API crates, binding crates, repo-wide Rust conventions). Several crates
also carry their own `CLAUDE.md` and substantive `README.md` (e.g. `bitwarden-state`,
`bitwarden-exporters`, `bitwarden-importers`, `bitwarden-ipc`, `bitwarden-threading`) — read the
crate's docs, `examples/`, and `tests/` before changing it.

## Commands

Toolchain: stable is pinned in `rust-toolchain.toml`; fmt, udeps, and dylint use the nightly pinned
there as `nightly-channel`. CLI tools (cargo-sort, cargo-dylint, cargo-udeps, …) are version-pinned
in `[workspace.metadata.bin]` and invoked via `cargo bin <tool>` (cargo-run-bin; source installs
only, no binstall).

Build & test:

- `cargo check --all-features --all-targets` — quick validation
- `cargo test --workspace --all-features` — full suite (what CI runs)
- `cargo test -p <crate> --all-features <filter>` — single crate / single test
- `cargo test --target wasm32-unknown-unknown -p bitwarden-wasm-internal -p bitwarden-threading -p bitwarden-error -p bitwarden-uuid --all-features`
  — WASM suite (matches CI; the test runner is wired up in `.cargo/config.toml`). Browser-dependent
  tests:
  `cargo test --target wasm32-unknown-unknown -p bitwarden-state --features wasm,browser-tests`
  (needs chromedriver).

Lint & format:

- `npm run lint` — every check CI runs (fmt, clippy, sort, udeps, dylint, doc, prettier,
  dep-ownership, cargo-lock); `npm run lint:fix` auto-fixes; `npm run lint -- --only <check>` runs
  one. Backed by `scripts/lint.sh`.
- **Never run bare `cargo fmt`** — `rustfmt.toml` uses nightly-only options that stable rustfmt
  silently ignores. Use `npm run lint:fix -- --only fmt`.
- Custom dylint lints live in `support/lints/` (not a workspace member).
- Husky pre-commit runs prettier, clippy, and dylint on staged files (plus udeps and sort when
  `Cargo.toml` changes) — commits are slow and can fail on lint.

Generated code:

- `bitwarden-api-api` / `bitwarden-api-identity` are generated from the server's OpenAPI specs —
  never edit by hand. Regenerate with `./support/build-api.sh` (expects a sibling `server` checkout)
  or the "Update API Bindings" GitHub workflow.
- WASM npm packages (`@bitwarden/sdk-internal`, `@bitwarden/commercial-sdk-internal`) build via
  `crates/bitwarden-wasm-internal/build.sh` (`-r` release, `-b` commercial).

## Architecture

Four layers; dependencies point strictly downward:

1. **Foundation** — `bitwarden-crypto`, `bitwarden-organization-crypto`, `bitwarden-state`,
   `bitwarden-threading`, `bitwarden-ipc`, `bitwarden-error`, `bitwarden-random` (the SDK's single
   CRNG source — use it instead of calling `rand::rng()` directly), plus small utilities. These must
   not depend on `bitwarden-core` or anything that does.
2. **Core** — `bitwarden-core` defines `Client`, a dependency-injection container (user identity,
   key store, API configuration, state). **Do not add features here** — feature crates extend
   `Client` via extension traits.
3. **Features** — one crate per domain (`bitwarden-vault`, `bitwarden-auth`, `bitwarden-send`,
   `bitwarden-generators`, `bitwarden-exporters`, `bitwarden-importers`, `bitwarden-sync`,
   `bitwarden-policies`, …). `bitwarden-pm` assembles them into `PasswordManagerClient`, the facade
   apps consume — one instance per user (`HashMap<UserId, PasswordManagerClient>`), lifecycle init →
   lock/unlock → logout (drop). The current sub-client list is in `crates/bitwarden-pm/src/lib.rs`.
4. **Bindings** — `bitwarden-uniffi` (Swift/Kotlin) and `bitwarden-wasm-internal`
   (TypeScript/JavaScript). Thin bindings only — no business logic.

## Code Review

For any code-review task (review PR / review changes / review this code / look at a diff), use the
repo-local **`reviewing-changes`** skill (`.claude/skills/reviewing-changes/SKILL.md`). It detects the
change type and loads the matching checklist (`checklists/*.md`) and reference sheets
(`reference/*.md`) for that kind of change. Treat this skill as the entry point for review work rather
than reviewing ad hoc.

The enforceable review rules live in the path-scoped `.claude/rules/` files (auto-loaded when you
touch matching files): `code-review.md` (cross-cutting power-user rules, with severities), alongside
the topic files `crypto.md`, `rust-conventions.md`, `bindings.md`, and `generated-api-crates.md`.

**Multi-agent review — forward the guidelines.** When a review runs in multi-agent mode, the
dispatching agent MUST forward the full contents of this `.claude/CLAUDE.md` and the loaded
`.claude/rules/` files (plus any near-file `README` / crate `CLAUDE.md`) to every review subagent.
Under the `evaluation-standards` gate a style/quality finding is only postable if its rule is written
in a file the subagent has loaded — a subagent that never received these rules cannot legitimately
raise them. Do not assume a subagent inherited this context; pass it explicitly.

## Deep-Dive Index

_Forthcoming — populated in Phase C._ This section will map each change-area to the `/docs/<page>.md`
deep-dive page the reviewer should read before reviewing that kind of change. The paths below are
placeholders and are NOT live yet:

- crypto / FFI change → `docs/patterns/crypto-safe-module.md` (Phase C)
- state / repository change → `docs/patterns/state-management.md` (Phase C)
- WASM / UniFFI binding change → `docs/patterns/bindings.md` (Phase C)

## References

- [SDK architecture](https://contributing.bitwarden.com/architecture/sdk/) ·
  [data models](https://contributing.bitwarden.com/architecture/sdk/data-models) ·
  [ADRs](https://contributing.bitwarden.com/architecture/adr/) ·
  [code style](https://contributing.bitwarden.com/contributing/code-style/) ·
  [security definitions](https://contributing.bitwarden.com/architecture/security/definitions)
