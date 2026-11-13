# Port categories

Pick the highest letter that applies. E and F usually decompose into smaller A–D ports; land those
first.

| #   | Category                      | Traits                                                     | Examples                                                        | Copy from                                                                                   | New infra                                                                                                                                |
| --- | ----------------------------- | ---------------------------------------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| A   | Pure crypto / logic           | No I/O, deterministic                                      | TOTP, rotateable key set, collection encryption, cipher risk    | `bitwarden-vault/src/totp.rs`, `bitwarden-wasm-internal/src/pure_crypto.rs`                 | Export only. Pin formats with `create-testvectors`.                                                                                      |
| B   | Stateless API action          | Endpoint calls, optional crypto, persists nothing          | Emergency access, org domains, cipher archive, change email     | `bitwarden-emergency-access` (one file per action + `*_client.rs`)                          | Generated API bindings; `XClient` with `#[derive(FromClient)]`, wired in `bitwarden-pm`, WASM, UniFFI.                                   |
| C   | CRUD + repository (id→record) | Encrypted domain object, list/get/create/edit, sync-driven | Folder, cipher, send, policy, organization                      | `bitwarden-vault/src/folder`                                                                | `register_repository_item!`, `create_client_managed_repositories!` entry, `SyncHandler`, host repository mappers (TS, Kotlin, Swift).    |
| D   | Per-user singleton state      | `UserKeyDefinition` singletons                             | Vault settings, billing profile, vault timeout settings, tokens | Settings: `register_setting_key!` (`client/persisted_state.rs`). KM: `state_bridge!`        | Setting key, or state bridge field (KM-owned, ask) — every host implements the generated bridge methods.                                 |
| E   | Stateful flow                 | Multi-step, API round-trips, state transitions, crypto     | Login strategies, key connector, auth request, TDE, lock        | `bitwarden-auth/src/login`, `bitwarden-core/src/auth`, `bitwarden-unlock`                   | Several of B–D plus cross-client composition. Split first.                                                                               |
| F   | Platform callback             | Needs host UI/OS: prompts, biometrics, IPC, secure storage | FIDO2, biometrics IPC, shared unlock, token provider            | `bitwarden-fido/src/traits.rs`, `bitwarden-server-communication-config/src/platform_api.rs` | Foreign trait (`uniffi::export(with_foreign)`, WASM import + `ThreadBoundRunner`), host impls in TS, Kotlin, Swift. Often its own crate. |
| G   | New domain                    | No crate yet                                               | Billing, admin auth requests                                    | `bitwarden-emergency-access`, `bitwarden-organization-domains`                              | New crate; wiring in `bitwarden-pm` (`commercial.rs` for licensed code), WASM, UniFFI; errors via `bitwarden-error`.                     |

## Consequences

- C, D, F touch all three hosts (repository factories, state bridges, foreign traits), even when
  porting from one origin. List the other hosts' required changes in the SDK PR.
- Origin unit specs shrink: tests of observable/DI wiring do not carry over. Behavior tests do.
- Mobile adopts via SDK version bump; clients via npm bump + flag-gated switch.

## Existing flag-gated switches (clients)

- Selector service swapping implementations: `Pm30110SdkSendsApi`,
  `libs/common/src/tools/send/services/send-api-service.selector.ts`.
- Per-call branch: `PM27060_PasswordPreloginFromSdk`,
  `libs/common/src/auth/password-prelogin/default-password-prelogin.service.ts`.
- Private `useSdk()` helper: `PM44303_EmergencyAccessSdkApi`,
  `apps/web/src/app/auth/emergency-access/services/emergency-access.service.ts`.
