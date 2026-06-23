# Bitwarden Internal SDK

## Purpose
A Rust monorepo that implements the core business logic of the Bitwarden password manager (cryptography, vault items, send, generators, auth, exporters, sync) and exposes it to the Bitwarden web/desktop/browser clients, iOS, and Android through WebAssembly and UniFFI bindings. The SDK is internal: its surface is unstable and may break between versions, and the official clients depend on it as a published npm package or a generated mobile binding. It does not ship as a public crate.

## Topology
A single Cargo workspace with two member roots: `crates/` (OSS, GPL-licensed) and `bitwarden_license/` (commercially-licensed crates such as `bitwarden-commercial-vault` and `bitwarden-sm`). The workspace is declared at `Cargo.toml:1-4`. Each crate produces one of three artifact shapes: a library consumed by other crates in the workspace, a binary (`crates/bw`, `crates/uniffi-bindgen`, `crates/wasm-bindgen-cli-runner`, `crates/memory-testing`), or a binding bundle that is later packaged into a non-Rust artifact (`bitwarden-wasm-internal` becomes the `@bitwarden/sdk-internal` npm package; `bitwarden-uniffi` becomes Kotlin and Swift bindings under `crates/bitwarden-uniffi/kotlin/` and `crates/bitwarden-uniffi/swift/`). The workspace pins Rust 2024 edition and rust-version 1.88, declared at `Cargo.toml:11-13`.

The repository also contains auto-generated OpenAPI bindings (`bitwarden-api-api`, `bitwarden-api-identity`, `bitwarden-api-base`, `bitwarden-api-key-connector`) regenerated from server Swagger documents via `support/build-api.sh`. These are checked in but should never be edited by hand.

## Entry points
There is no single entry point. Each binding crate exposes a top-level client type that is the SDK's entry point for that platform.

- WebAssembly: `crates/bitwarden-wasm-internal/src/client.rs:26` defines `PasswordManagerClient`, constructed via `#[wasm_bindgen(constructor)]` at line 32. `crates/bitwarden-wasm-internal/src/init.rs` provides `init_sdk()` for setting up panic hooks and logging on the JS side.
- UniFFI (iOS/Android): `crates/bitwarden-uniffi/src/lib.rs:43` defines `Client` (a `#[derive(uniffi::Object)]`), constructed via the `#[uniffi::constructor]` at line 49.
- Pure Rust callers: `crates/bitwarden-pm/src/lib.rs:45` defines `PasswordManagerClient`, the orchestrating entry type that both bindings wrap.

All three converge on `bitwarden_core::Client`, defined at `crates/bitwarden-core/src/client/client.rs:14`, which is the underlying object every feature client borrows.

## Major subsystems
The codebase is organized in four architectural layers (also documented in the project's `CLAUDE.md`).

**Foundation.**
- `bitwarden-crypto` (`crates/bitwarden-crypto/src/lib.rs`): cryptographic primitives, encrypted string formats, signing, and the `KeyStore` abstraction that holds key material behind opaque key references. The `safe` module exposes high-level wrappers (`PasswordProtectedKeyEnvelope`, data envelopes) that callers should prefer over raw primitives.
- `bitwarden-state` (`crates/bitwarden-state/src/lib.rs`): typed key-value `Repository` trait, plus a `StateRegistry` and a type-safe `Setting<T>` API for configuration. Backed by either client-managed storage (the host app implements the repository) or SDK-managed storage (SQLite, with migrations declared in `crates/bitwarden-pm/src/migrations.rs`).
- `bitwarden-threading`: `ThreadBoundRunner` for pinning `!Send` types to a single thread, used in WASM where many JS-backed types cannot cross thread boundaries.
- `bitwarden-ipc`: pluggable IPC framework with separable encryption and transport, used to communicate with browser-extension hosts.
- `bitwarden-error` / `bitwarden-error-macro`: a `#[bitwarden_error(...)]` proc-macro that generates platform-specific error bindings (WASM via `tsify`, UniFFI errors, FlatError trait) in `basic`, `flat`, or `full` modes.
- Supporting utility crates: `bitwarden-encoding`, `bitwarden-uuid`, `bitwarden-logging`.

**Core infrastructure.**
- `bitwarden-core` (`crates/bitwarden-core/src/lib.rs`): the `Client` struct and the `InternalClient` it wraps in an `Arc`. `InternalClient` (defined at `crates/bitwarden-core/src/client/internal.rs:111`) holds the `KeyStore`, the `StateRegistry`, the API configurations, the token handler, the optional `SecurityState`, and the `StateBridge`. Feature crates do not add fields to `Client`; instead they define extension traits that take `&Client` and return a feature-specific sub-client. The project rule, stated in the root `CLAUDE.md`, is do not add functionality to `bitwarden-core` itself, add a feature crate and extend.
- `bitwarden-api-*`: auto-generated request/response models and `ApiClient`s. Feature crates convert these to internal models via `From` / `TryFrom`, never re-exporting the generated types across the SDK boundary.

**Feature implementations.** Each is a self-contained crate that defines its own `XClient` struct holding a `bitwarden_core::Client` and an extension trait `XClientExt` for `Client` (the `vault()` accessor in `crates/bitwarden-vault/src/vault_client.rs:76` is representative). The set:
- `bitwarden-vault`: ciphers, folders, attachments, password history, TOTP, collections (`VaultClient` at `crates/bitwarden-vault/src/vault_client.rs:13`).
- `bitwarden-collections`: collection models and operations, separate from vault items.
- `bitwarden-auth`: login flows, session token handling, send access tokens.
- `bitwarden-send`: encrypted ephemeral file/text sharing.
- `bitwarden-generators`: password, passphrase, username generators.
- `bitwarden-exporters`: vault import/export across formats.
- `bitwarden-ssh`: SSH key generation and import.
- `bitwarden-fido`: FIDO2 second-factor support.
- `bitwarden-sync`: server sync orchestration and per-domain sync handlers (e.g. `FolderSyncHandler` registered in `crates/bitwarden-pm/src/lib.rs:82`).
- `bitwarden-policies`, `bitwarden-organizations`, `bitwarden-shared-unlock`, `bitwarden-user-crypto-management`: smaller features following the same pattern.
- `bitwarden-pm` (`crates/bitwarden-pm/src/lib.rs`): the password-manager *aggregator*. `PasswordManagerClient` wraps a `bitwarden_core::Client` and exposes typed accessors (`auth()`, `vault()`, `crypto()`, `sends()`, `generator()`, `exporters()`, `policies()`, `sync()`, `platform()`, `user_crypto_management()`). The `commercial()` accessor is only compiled with the `bitwarden-license` feature and gates access to `bitwarden_license/bitwarden-commercial-vault` and related crates.

**Cross-platform bindings.**
- `bitwarden-uniffi` (`crates/bitwarden-uniffi/src/lib.rs`): UniFFI scaffolding. The top-level `Client` (line 43) is a `uniffi::Object` whose methods mirror `PasswordManagerClient`. Logging is initialized via `init_logger` (line 197), which conditionally installs `tracing-oslog` on iOS and `tracing-android` (logcat) on Android. The `kotlin/` and `swift/` subdirectories contain the language-specific build scaffolding (Gradle and Swift Package, respectively).
- `bitwarden-wasm-internal` (`crates/bitwarden-wasm-internal/src/lib.rs`): WASM scaffolding. Thin bindings only, with no business logic. Structs are annotated with `#[derive(Tsify)]` to generate TypeScript types. The `npm/` subdirectory holds the package metadata that ships to npm. A `build.sh` and `build.rs` orchestrate the wasm-pack workflow. An `integration-tests/` directory holds JS-driven tests.

**Macro and tooling crates.** `bitwarden-core-macro`, `bitwarden-error-macro`, `bitwarden-ffi-macro`, `bitwarden-state-bridge-macro`, `bitwarden-test-macro`, `bitwarden-uuid-macro` provide the proc-macros referenced above. `bitwarden-test` provides shared test fixtures. `bw` is a small CLI binary, `uniffi-bindgen` runs UniFFI codegen, `memory-testing` exercises the zeroizing allocator under load.

## Data and state
Persistent state lives in two places, depending on the deployment.

For client-managed state (today's mobile and web clients), the host application implements the `Repository<T>` trait per registered type and hands the implementation to the SDK at startup. Repository registration happens via the `register_repository_item!` macro, and the active set is declared at the end of `crates/bitwarden-pm/src/migrations.rs` (see the example in `crates/bitwarden-state/README.md:48-60`).

For SDK-managed state, the SDK owns a SQLite database whose schema is built up by an ordered list of `RepositoryMigrationStep`s also declared in `crates/bitwarden-pm/src/migrations.rs`. Ordering of migrations is load-bearing: removing a repository requires its own `Remove(...)` step rather than deletion from the list.

A typed `Setting<T>` system layered on top of the registry stores non-bulk configuration. `crates/bitwarden-core/src/client/persisted_state.rs` declares keys such as `USER_ID`, `USER_LOGIN_METHOD`, `FLAGS`, and `SESSION_PROTECTED_USER_KEY`. Settings are accessed through `client.platform().state().setting(KEY)`, returning a `Setting<T>` handle that supports `get`, `update`, and `delete`.

In-memory state is held in `InternalClient` (`crates/bitwarden-core/src/client/internal.rs:111`). The `KeyStore<KeySlotIds>` (defined in `bitwarden-crypto`) holds decrypted user, organization, and ephemeral keys indexed by slot id; key material is never returned to callers, only references. A `OnceLock<UserId>` enforces that a client instance is bound to a single user for its lifetime (`init_user_id` at line 262). A `RwLock<Option<SecurityState>>` holds the signed account security state for V2 users.

Tokens are held by the configured `TokenHandler` (trait at `crates/bitwarden-core/src/auth/auth_tokens.rs`). Mobile and web clients pass a `ClientManagedTokenHandler` so the host stays the source of truth for the access and refresh tokens; the CLI uses an SDK-managed handler.

## A representative flow
A vault unlock from a mobile client, traced end-to-end.

1. The host app instantiates the binding: `Client::new(token_provider, settings)` at `crates/bitwarden-uniffi/src/lib.rs:49` initializes logging and wraps a `bitwarden_pm::PasswordManagerClient`.
2. `PasswordManagerClient::new_with_client_tokens` at `crates/bitwarden-pm/src/lib.rs:63` constructs an underlying `bitwarden_core::Client` via `Client::new_with_token_handler` (`crates/bitwarden-core/src/client/client.rs:36`), which builds the `InternalClient` with its `KeyStore`, `StateRegistry`, and API configurations.
3. The host calls `client.crypto()` to obtain a `CryptoClient`, then invokes the unlock method appropriate to the user (master-password, PIN, or biometric). For master-password unlock, the call path enters `InternalClient::initialize_user_crypto_master_password_unlock` at `crates/bitwarden-core/src/client/internal.rs:407`.
4. That method calls `MasterKey::derive(password, salt, kdf)` to derive the wrapping key, then `master_key.decrypt_user_key(wrapped_user_key)` to produce the user's symmetric key.
5. Control passes to `initialize_user_crypto_decrypted_key` (line 302), which inserts the key into the `KeyStore` via `ctx.add_local_symmetric_key`, optionally upgrades a V1 AES key to a V2 XChaCha20 key using a `V2UpgradeToken`, and then commits the account cryptographic state through `account_crypto_state.set_to_context`. The local context is dropped without persisting if any step fails, preventing partial setup.
6. With keys loaded, `client.is_unlocked()` (`crates/bitwarden-pm/src/lib.rs:148`) now returns true because `SymmetricKeySlotId::User` is populated.
7. Subsequent calls such as `client.vault().ciphers().list()` route through `VaultClient` (`crates/bitwarden-vault/src/vault_client.rs:13`) to `CiphersClient`, which decrypts ciphers loaded from the `Repository<Cipher>` (client- or SDK-managed) using the `KeyStore` context.

## Cross-cutting concerns

**Logging.** `tracing` workspace-wide. The UniFFI binding installs `tracing-oslog` (iOS) or `tracing-android` (Android) plus an optional host callback layer via `LogCallback` (`crates/bitwarden-uniffi/src/lib.rs:197-258`). The WASM binding installs a JS-bridged tracing layer in `crates/bitwarden-wasm-internal/src/init.rs`. HTTP traffic is wrapped by `ReqwestTracingMiddleware` (`crates/bitwarden-core/src/client/tracing_middleware.rs`).

**Error handling.** Every error type that needs to cross a binding boundary is annotated with `#[bitwarden_error(basic|flat|full)]` (from `bitwarden-error-macro`). The macro generates TypeScript interfaces for WASM and `uniffi::Error` impls for UniFFI. Internal Rust errors use `thiserror`. A dedicated `bitwarden-uniffi-error` crate registers a converter (`setup_error_converter` at `crates/bitwarden-uniffi/src/lib.rs:262`) so that conversion failures never panic into FFI.

**Feature flags.** Compile-time flags `internal`, `secrets`, `uniffi`, `wasm`, `bitwarden-license`, and `test-fixtures` gate large sections of code. Runtime feature flags are stored in the `FLAGS` setting and read via `InternalClient::get_flags` (`crates/bitwarden-core/src/client/internal.rs:156`).

**Telemetry.** No external telemetry. A `FlightRecorder` (`crates/bitwarden-wasm-internal/src/flight_recorder.rs`) buffers logs in memory for the WASM host to retrieve on demand. `memory-testing` is a binary for stress-testing the `ZeroizingAllocator` exported from `bitwarden-crypto`.

**Configuration.** `ClientSettings` (`crates/bitwarden-core/src/client/client_settings.rs`) holds API URLs, identity URL, user agent, and device type. Server-communication policy (cookies, host bootstrap) is delegated to a `CookieProvider` registered via `with_server_communication_config` on the builder.

**Auth & token management.** The `TokenHandler` trait abstracts where tokens live. `ClientManagedTokenHandler` (`crates/bitwarden-core/src/auth/auth_tokens.rs`) defers to a host-supplied `ClientManagedTokens`; the WASM binding uses `WasmClientManagedTokens` (`crates/bitwarden-wasm-internal/src/platform/token_provider.rs`), the UniFFI binding uses an Arc-supplied `ClientManagedTokens` from Kotlin/Swift.

## Build, test, run
Project-standard commands, taken from the root `CLAUDE.md` and `package.json`:

- `cargo check --all-features --all-targets`: quick validation.
- `cargo test --workspace --all-features`: full Rust test suite. `cargo nextest run --all-features` is the recommended alternative once `cargo-nextest` is installed.
- `cargo +nightly fmt --workspace`: formatting (nightly required because of unstable rustfmt options in `rustfmt.toml`).
- `cargo clippy --all-features --all-targets`: linting. The workspace denies `unwrap_used`, `disallowed-macros`, and warns on `unused_async`, `print_stdout`, `print_stderr`, `string_slice`, and `missing_docs` (declared in `Cargo.toml:125-137`).
- `cargo dylint --all`: custom lints from `support/lints`.
- WASM tests: `cargo test --target wasm32-unknown-unknown --features wasm -p bitwarden-error -p bitwarden-threading -p bitwarden-uuid`.
- WASM build: `crates/bitwarden-wasm-internal/build.sh` (with `-b` to include commercial code).
- iOS/Android builds: scripts under `crates/bitwarden-uniffi/kotlin/` and `crates/bitwarden-uniffi/swift/`, plus `publish-local.sh` for local Maven publishing.
- Regenerating API bindings: `./support/build-api.sh` (requires a sibling `server/` checkout and a JRE). Binding changes must merge through the `Update API Bindings` GitHub workflow, not via hand-edited PRs.

A `bacon.toml` at the repo root configures the optional `bacon` background checker with `check`, `clippy`, `test`, and `doc` jobs.

## Notable assumptions and constraints

**A `Client` is bound to one user for its lifetime.** `InternalClient::user_id` is a `OnceLock<UserId>`, set by `init_user_id` (`crates/bitwarden-core/src/client/internal.rs:262`). Switching users requires constructing a new client; host apps maintain a `HashMap<UserId, PasswordManagerClient>` to support multi-account.

**Cloning `Client` clones an `Arc`, not the state.** The struct is documented (`crates/bitwarden-core/src/client/client.rs:14-21`) as relying on `Clone` returning a handle to the same `InternalClient`, which is required for FFI where Rust references cannot survive the boundary. Adding non-`Arc` mutable state to `Client` would silently break the FFI contract.

**Key material never leaves `KeyStore`.** `KeyStoreContext` references are not held across `await` points (root `CLAUDE.md`), and the crypto crate exposes key handles rather than bytes. The `dangerous-crypto-debug` feature exists to log key material during development; the binding crates emit a runtime warning when it is enabled.

**Encryption format compatibility is permanent.** The SDK must continue to decrypt data encrypted by every prior version, because users may upgrade across arbitrary version gaps. Breaking on-disk format changes require an explicit upgrade path (e.g. the V1→V2 user-key upgrade via `V2UpgradeToken` in `internal.rs:314-326`).

**Auto-generated API crates are immutable in this repo.** Edits to `bitwarden-api-api`, `bitwarden-api-identity`, `bitwarden-api-base`, `bitwarden-api-key-connector` are overwritten by the regeneration workflow. Mappings from these generated models to SDK-internal models live in feature crates as `From`/`TryFrom` impls.

**Two licensing tracks coexist in one workspace.** Crates under `bitwarden_license/` are GPL-incompatible commercial code and must be excluded from OSS builds. The `bitwarden-license` Cargo feature on `bitwarden-pm` and `bitwarden-wasm-internal` is the gate; building without it produces the OSS-only npm package, building with it produces the commercial package that includes both.

**The browser/Web Worker context is `!Send`.** Many WASM-bridged types hold a `JsValue` and cannot move between threads. The project requires wrapping such types in `ThreadBoundRunner` rather than using `#[async_trait(?Send)]`, with two named exceptions: the generated `bitwarden-api-*` crates and `reqwest_middleware::Middleware` impls.

**SDK-managed state is not yet usable from WASM or UniFFI clients.** As noted in `crates/bitwarden-state/README.md:164-176`, the SDK-managed path lacks migrations, secure storage, reactivity, and browser-extension sync. Mobile and web clients therefore use client-managed state today; SDK-managed state is reserved for the CLI and future flows.
