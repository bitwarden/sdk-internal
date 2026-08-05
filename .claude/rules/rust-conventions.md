---
paths:
  - "crates/**/*.rs"
  - "bitwarden_license/**/*.rs"
---

# Rust conventions

## Data models

Model layers use suffixes (full picture:
[data models docs](https://contributing.bitwarden.com/architecture/sdk/data-models)):

| Suffix     | Role                                  | Example               |
| ---------- | ------------------------------------- | --------------------- |
| _(none)_   | Server/storage-layer model            | `Cipher`, `Send`      |
| `View`     | Decrypted DTO returned to clients     | `CipherView`          |
| `Request`  | Public input DTO from client into SDK | `CipherCreateRequest` |
| `Response` | Public output DTO from SDK to client  | `LoginResponse`       |

- Prefer `View`/`Request`/`Response` at API boundaries.
- Use separate `*CreateRequest` / `*EditRequest` structs when create and edit fields differ (e.g.
  edit requires an `id` or `revision_date`).
- Variant data: when a model has a type discriminant with per-variant data (a send is file or text,
  never both), use an enum with associated data — not a discriminant field plus multiple `Option`s.
  Map the server wire format (numeric discriminant + optional fields) to the domain enum at the
  API→domain boundary.

## Threading

Do not use `#[async_trait(?Send)]` in hand-written code. Wrap `!Send` values (e.g. JS `extern "C"`
bindings holding `JsValue`) in `ThreadBoundRunner` from `bitwarden-threading`, which is
`Send + Sync`. Exceptions: the generated `bitwarden-api-*` crates and
`reqwest_middleware::Middleware` impls, which must mirror the upstream `?Send` declaration on
wasm32.

## Exposing types across bindings

- UniFFI: `#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]` on structs, `uniffi::Enum` on
  enums; crates with UniFFI exports call `uniffi::setup_scaffolding!()` in `lib.rs`.
- WASM: `#[derive(Serialize, Deserialize)]` plus
  `#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]`.
- Errors: annotate with `bitwarden-error` (`basic`/`flat`/`full` modes) to generate the WASM,
  TypeScript, and UniFFI error bindings.

## Security

- Never log or embed keys, passwords, or vault data in log output or error messages.
- Existing encrypted data must remain decryptable: encryption and serialization changes must stay
  backward compatible.
