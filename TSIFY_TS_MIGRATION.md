# Migrating off `tsify(into_wasm_abi, from_wasm_abi)`

Working document for the migration away from tsify's deprecated ABI attributes and onto `Ts<T>`.
Delete this file when the migration is finished.

## Why

`#[tsify(from_wasm_abi)]` makes `FromWasmAbi::from_abi` do the serde deserialization. That function
returns `Self`, not `Result<Self, _>`, so the generated impl has no way to report failure and calls
`wasm_bindgen::throw_str`. That raises a JavaScript exception which unwinds straight past the wasm
frames **without running destructors**, leaking everything alive at that point — the serde error,
the partially deserialized value, and every argument already converted before the failing one.

From JavaScript it looks like an ordinary catchable exception, so an application can appear to
handle bad input correctly while its wasm heap grows on every failure. This has been hit in
production. Upstream: [tsify#65](https://github.com/madonoharu/tsify/issues/65).

Direction matters:

- **`from_wasm_abi`** (parameters, JS → Rust) is the leak. `throw_str`, no destructors.
- **`into_wasm_abi`** (returns, Rust → JS) uses `panic!`, which aborts on wasm. Bad, but not a
  silent leak.

tsify 0.5.7 deprecated both attributes and added `Ts<T>` as the fix. `Ts<T>` is a
`#[repr(transparent)]` wrapper that crosses the ABI as a plain JS handle; conversion happens inside
the function body, where a failure is an ordinary `Err` and destructors run.

## Why this needs a macro

`Ts<T>` has to appear in the signature, which collides with the pattern used throughout this repo —
one Rust function exported to several targets at once:

```rust
#[cfg_attr(feature = "uniffi", uniffi::export)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub async fn create(&self, request: CipherCreateRequest) -> Result<CipherView, CreateCipherError>
```

`Ts<CipherCreateRequest>` cannot be slotted in without breaking the UniFFI export and every Rust
caller. This is exactly [tsify#93](https://github.com/madonoharu/tsify/issues/93), which is open,
has no PR, and has unresolved design questions. The decision was to solve it locally in
`bitwarden-ffi-macro` rather than wait, and optionally upstream the design later.

`#[wasm_export]` generates a **second** impl block of shims beside the original, so the original
methods keep their plain Rust signatures and only JavaScript sees `Ts<T>`.

## Scope

200+ deprecation sites remain on `main`. Not every tsify type is affected — a type only needs the
attributes if it appears in a wasm-exported signature — but the compiler decides that, not us (see
[Safety net](#safety-net)).

Phase 2 is one PR per codeowner, so the split that matters is by owner:

| Codeowner                                       | Crates                                                                                                                                                                                                      |
| ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `team-vault-dev`                                | `bitwarden-vault`                                                                                                                                                                                           |
| `team-auth-dev`                                 | `bitwarden-auth`                                                                                                                                                                                            |
| `team-tools-dev`                                | `bitwarden-send`, `bitwarden-importers`, `bitwarden-exporters`, `bitwarden-ssh`, `bitwarden-generators`                                                                                                     |
| `team-pam-dev`                                  | `bitwarden-pam`                                                                                                                                                                                             |
| `team-platform-dev`                             | `bitwarden-core` (non-`key_management`), `bitwarden-ipc`, `bitwarden-server-communication-config`, `bitwarden-encoding`, `bitwarden-logging`, `bitwarden-managed-settings-types`, `bitwarden-wasm-internal` |
| `team-key-management-dev` + `team-platform-dev` | `bitwarden-core/src/key_management/**`                                                                                                                                                                      |
| `team-key-management-dev`                       | `bitwarden-crypto`, `bitwarden-user-crypto-management`, `bitwarden-crypto-sync-handler`, `bitwarden-shared-unlock`                                                                                          |
| `team-admin-console-dev`                        | `bitwarden-policies`, `bitwarden-collections`, `bitwarden-organizations`, `bitwarden-organization-invite-link`                                                                                              |

`bitwarden-generators` (`team-tools-dev`) was the proof of concept and is the reference to copy
from.

Counts per crate, when sizing the PRs:

```bash
cargo check --all-features 2>&1 | grep -A2 'deprecated constant' \
  | grep -oE '\-\-> [a-zA-Z0-9_/.-]+\.rs' | sed 's/--> //' | sort | uniq -c | sort -rn
```

## Landing plan

The ordering matters and is not obvious. `Ts` only exists from tsify 0.5.7, and 0.5.7 is also the
version that deprecates the attributes. Since `scripts/lint.sh` exports `RUSTFLAGS="-D warnings"`,
bumping tsify turns every one of those warnings into a hard error in `npm run lint` on every PR. So
the tsify bump cannot land before the migration is complete, and the migration cannot start before
`Ts` exists.

The way out is to split the macros' introduction from their behaviour, so the per-team PRs are pure
attribute replacements and every decision that needs judgement lives in `team-platform-dev`'s code.

### Phase 1 — pass-through macros (one PR, `team-platform-dev`)

Land all three macros with their final placement contract but today's behaviour:

- `#[wasm_export]` emits `#[cfg_attr(feature = "wasm", wasm_bindgen(..))]` verbatim, keeping the
  existing `#[wasm_only]` behaviour.
- `#[wasm_record]` emits
  `#[cfg_attr(feature = "wasm", derive(Tsify), tsify(into_wasm_abi, from_wasm_abi))]`.
- `#[wasm_object]` emits `#[cfg_attr(feature = "wasm", wasm_bindgen(..))]`.

No `Ts`, no wire traits, no tsify bump. Behaviour is unchanged and lint stays green.

Two requirements that are easy to get wrong:

- **Each macro must replace the attribute it stands in for, not sit above it.** Phase 1 has to
  establish the final placement so phase 3 only changes the macro bodies — otherwise phase 3 has to
  revisit every call site to delete a now-duplicated attribute, defeating phase 2.
- **`#[wasm_record]` must not consume `#[serde(..)]` or `#[tsify(..)]`.** `Tsify`'s derive reads
  both off the item, and field-level `#[cfg_attr(feature = "wasm", tsify(type = ".."))]` has to
  survive untouched.

### Phase 2 — adopt the macros (one PR per codeowner, parallel)

Mechanical attribute replacement, nothing else:

| From                                                           | To               |
| -------------------------------------------------------------- | ---------------- |
| `#[cfg_attr(feature = "wasm", derive(Tsify), tsify(..))]`      | `#[wasm_record]` |
| `#[cfg_attr(feature = "wasm", wasm_bindgen)]` on a struct/enum | `#[wasm_object]` |
| `#[cfg_attr(feature = "wasm", wasm_bindgen)]` on an impl block | `#[wasm_export]` |

Each PR is behaviourally a no-op, verified by the generated `.d.ts` being unchanged (see
[Verification](#verification)). Crates gain a `bitwarden-ffi` dependency and `bitwarden-ffi/wasm` in
their `wasm` feature. These can run in parallel across teams.

Do **not** remove the tsify attributes in this phase — `#[wasm_record]` still emits them, and they
are load-bearing until phase 3.

The five sites in [Needed more than a swap](#needed-more-than-a-swap) do not fit the table. Fold
them into the platform PRs rather than asking each team to work them out.

### Phase 3 — flip the switch (one PR, `team-platform-dev`)

Because phase 2 moved every decision into the macros, this phase touches no feature crate:

1. Add the [wire traits](#wire-traits-fromwasm--towasm) to `bitwarden-ffi`.
2. Change the three macro bodies: `#[wasm_record]` drops the tsify ABI attributes and emits
   `impl_wire_record!`, `#[wasm_object]` emits `impl_wire_object!`, and `#[wasm_export]` projects
   onto `<T as FromWasm>::Wire` / `<T as ToWasm>::Wire`.
3. Bump `tsify` to `>=0.5.7, <0.6` in the workspace `Cargo.toml` and update `Cargo.lock`.
4. Replace the `#[tsify(into_wasm_abi)]` in `bitwarden-error-macro`'s `full` mode with a
   hand-written `From<E> for JsValue`. Note this also drops `IntoWasmAbi` and `WasmDescribe` from
   `full` errors — only `Into<JsValue>` is needed in a `Result`'s error position, but a `full` error
   used as a _value_ in a wasm signature would stop compiling. Neither of the two in the tree is.

At the moment this PR lands there are zero deprecations left, so `-D warnings` is satisfied
throughout.

This is the payoff of the wire traits over an inference heuristic. With inference, phase 3 also has
to add `ts = false` and `#[ts(skip)]` across 30 crates, which is per-crate judgement work landing in
the one coordinated PR. With projections there is nothing to decide: the type already declared its
wire form in phase 2.

## Safety net

This is what makes the migration safe to do incrementally and by different teams.

Once a type loses its attributes, **both** kinds of mistake are compile errors:

- A value that should have been converted but was not → `T: FromWasmAbi` unsatisfied.
- A value that was converted but should not have been (a `#[wasm_bindgen]` handle) → `T: Tsify`
  unsatisfied.

The compiler names the exact site in both cases. So the inference heuristic in the macro does not
need to be right, only useful, and a missed conversion cannot silently keep leaking.

The end-state invariant is greppable: **zero occurrences of `from_wasm_abi` in the tree means zero
leaking paths.**

A dylint rule to prevent reintroduction was considered and rejected: `lint.yml` runs
`cargo clippy --all-features --all-targets -- -D warnings` on every pull request with no path
filter, so a reintroduced attribute is already a hard error, covering both directions and firing on
`.rs`-only changes.

## Verification

The acceptance test for phases 2 and 3 is that the generated TypeScript is unchanged. Build
`--release`, for the reason in the next section, and generate the `.d.ts`:

```bash
cargo build -p bitwarden-wasm-internal --target wasm32-unknown-unknown --release
cargo run -q -p wasm-bindgen-cli-runner --bin wasm-bindgen-runner -- \
  --target bundler --out-dir /tmp/dts-after \
  ./target/wasm32-unknown-unknown/release/bitwarden_wasm_internal.wasm
```

Capture `/tmp/dts-baseline` the same way from `main` before starting — from a separate worktree, so
you are not rebuilding the same target directory back and forth. A worktree needs `RUSTUP_TOOLCHAIN`
set to whatever this checkout resolves to, or it picks up the pinned channel without the
`wasm32-unknown-unknown` target installed.

A plain `diff` will not be empty, for two reasons that are both benign and neither of which a byte
comparison can see past:

- tsify 0.5.7 stopped escaping apostrophes and quotes inside doc comments (`The organization\'s` →
  `The organization's`), and fixed a bug that split a line on a trailing `"`. JSDoc text only.
- Declarations move, because the shims live in a second impl block. Constructors and methods reorder
  within a class, fields within an interface.

So assert on the exported symbol set, and on content only after normalizing escaping and order. Both
of these are empty for a release build:

```bash
BASE=/tmp/dts-baseline/bitwarden_wasm_internal.d.ts
AFTER=/tmp/dts-after/bitwarden_wasm_internal.d.ts
sym() { grep -oE '^export (interface|enum|class|type|declare) [A-Za-z0-9_]+' "$1" \
  | awk '{print $NF}' | sort -u; }
norm() { sed "s/\\\\'/'/g; s/\\\\\"/\"/g" "$1" | sed 's/^[[:space:]]*//' | sort; }
diff <(sym "$BASE") <(sym "$AFTER")
diff <(norm "$BASE") <(norm "$AFTER")
```

Also worth running per crate: `cargo test -p <crate> --all-features`, and for any crate with UniFFI
or CLI consumers, `cargo check -p bitwarden-uniffi -p bw` — those are what prove the Rust-facing
signatures did not move.

### Resolved: debug builds used to drop nested-only types

Deleting the tsify attributes without also adopting the wire traits made a debug wasm build emit a
`.d.ts` missing eleven types — `KeyConnectorUserDecryptionOption`,
`TrustedDeviceUserDecryptionOption`, `WebAuthnPrfUserDecryptionOption`, `ProfileOrganization`,
`Permissions`, `RotateableKeySet`, `OrganizationUserStatusType`, `OrganizationUserType`,
`MemberDecryptionType`, `ProductTierType`, `ProviderType`. Five were still referenced by types that
remained, so the file was not valid TypeScript, not merely incomplete.

`#[tsify(into_wasm_abi)]` had been anchoring them: it generated an `IntoWasmAbi` impl reachable from
an exported function, which kept the type's `#[wasm_bindgen(typescript_custom_section)]` alive
through `wasm-ld`. Every affected type appears only _nested_ inside another type, never directly in
a wasm-exported signature, so nothing else referenced it. Release masked this via
`codegen-units = 1`, the same way `.claude/CLAUDE.md` describes.

[The wire traits](#wire-traits-fromwasm--towasm) fix it as a side effect, with no dummy export
needed: `impl_wire_record!` generates `type Wire = Ts<Self>`, `Ts<T>` names `<T as Tsify>::JsType`,
and that reference sits in the same const block as the custom section. Debug and release now emit
the same 393 symbols, byte-identical after normalization.

Worth keeping in mind if the wire traits are ever backed out: it is the _reference from an
instantiated item_, not the attribute, that keeps the section. `tsify-macros-0.5.8` emits both the
`extern "C" { pub type JsType; }` block and the custom section unconditionally
(`src/wasm_bindgen.rs`, lines 89 and 107); only `WasmDescribe` and the `IntoWasmAbi` / `FromWasmAbi`
families are gated on the attributes (lines 33-65).

## How the macro works

`#[wasm_export]` on a plain impl block (no `#[wasm_bindgen]` above it) leaves the original methods
exactly as written and generates a second `#[cfg(feature = "wasm")] #[wasm_bindgen]` impl block of
shims beside them.

```rust
#[wasm_export]
impl GeneratorClient {
    pub fn password(&self, input: PasswordGeneratorRequest) -> Result<String, PasswordError> {
        password(input)
    }
}
```

roughly becomes:

```rust
impl GeneratorClient {
    pub fn password(&self, input: PasswordGeneratorRequest) -> Result<String, PasswordError> { .. }
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
impl GeneratorClient {
    #[wasm_bindgen(js_name = "password")]
    #[doc(hidden)]
    pub fn __wasm_ts_password(
        &self,
        input: Ts<PasswordGeneratorRequest>,
    ) -> Result<String, TsError<PasswordError>> {
        let input = input.to_rust().map_err(TsError::Conversion)?;
        self.password(input).map_err(TsError::Inner)
    }
}
```

Notable behaviours:

- **Every `pub` method is shimmed**, matching wasm_bindgen's own rule. Shimming only the methods
  that convert something would silently unexport the rest, since the original block no longer
  carries `#[wasm_bindgen]`.
- **Every shim is fallible**, including the ones where nothing can fail. There is one code path, not
  a special case for methods that convert nothing. See
  [Shims that gained a `Result`](#shims-that-gained-a-result).
- **Conversion is not inferred** — see [wire traits](#wire-traits-fromwasm--towasm). References pass
  through untouched, which the macro reads off the tokens rather than guessing.
- **Errors keep their identity.** `Result<T, E>` becomes `Result<_, TsError<E>>`, and
  `TsError::Inner` delegates to `E`'s own `From<E> for JsValue`, so a `bitwarden_error` type reaches
  JavaScript with the `name` and `variant` it already had. No downstream error enum needed widening.
  Conversion failures surface as an `Error` named `SdkConversionError`
  (`bitwarden_error::wasm::CONVERSION_ERROR_NAME`) — the same name `full` mode uses when the error
  payload itself fails to serialize, so one `error.name` check covers both directions.
- **Method `#[wasm_bindgen(..)]` attributes move onto the shim** — needed for the `js_name`,
  `constructor` and `unchecked_return_type` methods in the tree, of which there are many.

### Wire traits: `FromWasm` / `ToWasm`

A proc macro cannot resolve types. Seeing the token `CipherView`, `#[wasm_export]` has no way to
know whether that is a serde DTO, which must cross as `Ts<T>`, or a `#[wasm_bindgen]` handle, which
crosses as itself. The first cut guessed from a closed list of primitives and let the compiler
reject wrong guesses, which worked but pushed an `#[ts(..)]` annotation onto every site the guess
got wrong.

Instead, each type declares its own wire form in `bitwarden-ffi/src/wire.rs`:

```rust
pub trait FromWasm: Sized {
    type Wire;
    fn from_wire(wire: Self::Wire) -> Result<Self, tsify::Error>;
}
```

`#[wasm_record]` generates `type Wire = Ts<Self>`; `#[wasm_object]` generates `type Wire = Self`.
The macro then only has to spell a projection, and the type decides what it resolves to:

```rust
pub fn __wasm_ts_password(
    &self,
    input: <PasswordGeneratorRequest as FromWasm>::Wire,
) -> Result<<String as ToWasm>::Wire, TsError<PasswordError>> { .. }
```

Blanket impls on `Vec<T>` and `Option<T>` set `Wire = Vec<T::Wire>` / `Option<T::Wire>`, so nesting
composes without special cases and `Vec<u8>` still reaches JavaScript as a `Uint8Array`. `Ts` lands
on the leaf, never the container — `Ts<Vec<T>>` is not something tsify supports. An identity impl on
`Ts<T>` lets a hand-written signature name the wire type directly, which is what `bitwarden-ipc`'s
accessors rely on.

This strengthens the [safety net](#safety-net): rather than two different unsatisfied bounds
depending on which way the guess went wrong, there is one trait, and a type that has declared
neither kind simply does not compile.

Known limits, both verified:

- **`Vec<Option<T>>` does not work**, in either design. `Vec<Option<Ts<T>>>` needs
  `Option<Ts<T>>: ErasableGeneric`, which wasm_bindgen does not provide. Nothing in the tree uses
  the shape.
- **Every shim is now fallible.** The macro cannot know whether a given type's conversion can fail,
  so it wraps unconditionally. See [Methods that gained a `Result`](#shims-that-gained-a-result).

### Escape hatches

| Where      | Attribute                        | Effect                                                                                                             |
| ---------- | -------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| impl block | `#[wasm_export(js_class = Foo)]` | Any argument is forwarded to the generated `#[wasm_bindgen]`.                                                      |
| type       | `#[wasm_object(js_name = Foo)]`  | Same, forwarded to the `#[wasm_bindgen]` on the type.                                                              |
| method     | `#[wasm_only]`                   | Method is only for JavaScript. Renamed `__wasm_only_*`, `#[doc(hidden)]`, `#[deprecated]`. Optional `note = ".."`. |

There is no per-value override, because there is nothing to override. `ts = false`, `#[ts(skip)]`,
`#[ts(ret)]` and `#[ts(skip_ret)]` were all artefacts of inference and are gone. A foreign type that
needs to cross bare gets an `impl_wire_object!` line in `wire.rs`, which is one central place rather
than an annotation at every call site.

`state_bridge!` has its own unrelated `#[ts(skip)]`; see [state bridge](#state-bridge).

## Work already done

All of it is on an uncommitted working tree that **conflates all three phases** — the whole
migration is done at once, so it has to be re-cut rather than landed as-is. There are zero
deprecation sites and zero un-migrated `#[cfg_attr(feature = "wasm", wasm_bindgen)]` impl blocks
left in it.

Infrastructure, all of which is phase 1 or phase 3:

- `crates/bitwarden-ffi-macro/` — `#[wasm_export]`, `#[wasm_record]`, `#[wasm_object]`. Replaces the
  previous `wasm_export`/`wasm_only` macro, which sat above `#[wasm_bindgen]`.
- `crates/bitwarden-ffi/src/wire.rs` — `FromWasm` / `ToWasm`, the container and `Ts<T>` blanket
  impls, the primitive set, and the `impl_wire_record!` / `impl_wire_object!` helpers the two
  type-level macros expand to.
- `crates/bitwarden-ffi/src/ts.rs` — `TsError<E = Never>` and `CONVERSION_ERROR_NAME`; re-exports
  `tsify::Ts`.
- `crates/bitwarden-error-macro/src/full/attribute.rs` — phase 3 item 4.
- `Cargo.toml` — tsify floor raised to `>=0.5.7`. Belongs in phase 3.
- Tests: `crates/bitwarden-ffi/tests/wasm_export.rs` — native and wasm cases, including a regression
  test that malformed input returns `Err(TsError::Conversion)` rather than taking the `throw_str`
  path, and function-pointer coercions that assert each generated shim signature exactly; one
  trybuild compile-fail case; expansion tests for all three macros in `bitwarden-ffi-macro`. The
  macros' error paths (arguments on `#[wasm_record]`, a generic type, a non-struct/enum item) have
  no compile-fail coverage yet.
- `crates/bitwarden-wasm-internal/Cargo.toml` — depends on `bitwarden-ffi` with `wasm` so the
  feature is on for the whole wasm build graph. Adopting crates should **also** add
  `bitwarden-ffi/wasm` to their own `wasm` feature, or `cargo check -p <crate> --features wasm` in
  isolation fails on a missing `Ts`.

Everything else is phase 2 and 3 per-crate adoption, across every crate in the [Scope](#scope)
table: 202 `#[wasm_record]` sites, 73 `#[wasm_object]` sites (58 from `cfg_attr`, 15 from a bare
`#[wasm_bindgen]`), 53 `#[ts(..)]` deletions, and 11 crates gaining the `bitwarden-ffi` dependency.
173 files, and a net deletion. `crates/bitwarden-generators/` is the cleanest one to read first.

Verified on the full tree: `cargo check --all-features --all-targets` (no warnings),
`cargo test --workspace --all-features` (2427 passing), the CI wasm suite, wasm32 debug and release
builds, and `npm run lint` — all clean except `dylint`, which fails locally for an unrelated reason
(see [below](#things-that-cost-time-so-you-do-not-rediscover-them)). The generated `.d.ts` is
393/393 symbols with zero normalized content difference in **both** debug and release.

### Needed more than a swap

Five categories the phase 2 table does not cover. Together they are ~30 sites, all of them
platform-owned.

1. **`extern "C"` handles.** `#[wasm_bindgen] extern "C" { pub type X; }` cannot carry
   `#[wasm_object]`, so the wire impl goes beside the block: `AbortController`, `AbortSignal`
   (`bitwarden-threading`), `RawWasmStateBridge` (`bitwarden-core`),
   `RawJsServerCommunicationConfigRepository`, `RawJsServerCommunicationConfigPlatformApi`,
   `JsTokenProvider`, `RawJsSharedUnlockDriver`, `RawJsBiometricsDriver`,
   `JsCommunicationBackendSender`, `RawJsSessionRepository`. Watch the enclosing scope — several sit
   inside a `mod wasm` or behind `#[cfg(target_arch = "wasm32")]` rather than `feature = "wasm"`,
   and the impl has to match.
2. **Types that hand-roll their own ABI.** Thirteen types implement `FromWasmAbi`/`IntoWasmAbi`
   themselves, crossing as a string: `EncString`, `UnsignedSharedKey`, `KeyId`, `PublicKey`,
   `SymmetricCryptoKey`, `DataEnvelope`, `HighEntropySecret`, `PasswordProtectedKeyEnvelope`,
   `SecretProtectedKeyEnvelope`, `SymmetricKeyEnvelope`, `SensitiveString`, `Invite`,
   `InviteSecret`, `SealedOpenOrgInviteData`. They are `object`-kind and need `impl_wire_object!`,
   not `#[wasm_record]` — they have no `Tsify` impl at all.
3. **Macro-generated types.** `bitwarden-uuid-macro` emits the `Tsify` derive for every
   `uuid_newtype!`, and `create_wasm_repositories!` emits the `Repositories` container as an extern
   type. Both macros emit the wire impl themselves, which means every crate calling them needs the
   `bitwarden-ffi` dependency.
4. **`bitwarden-error` cannot participate.** `bitwarden-ffi` depends on it, so it cannot depend
   back. If `SdkJsError` ever needs a wire impl it has to live in `wire.rs`, where the trait is
   local. Nothing needs it today.
5. **Attribute forms the sweep misses.** A multi-line `cfg_attr` (6 sites in `bitwarden-exporters`
   and `bitwarden-importers`), `derive(Tsify, Serialize, Deserialize)` where the serde derives are
   also wasm-only (`AncestorMap`, `cxf/export.rs`), and three bare `#[derive(Tsify)]` in crates with
   no non-wasm build (`b64.rs`, `platform/mod.rs`, and the `bitwarden-threading` test).

### Shims that gained a `Result`

**No source signature changes.** The methods below are written exactly as they were; what gained the
`Result` is the generated `__wasm_ts_*` shim beside them, which is `#[doc(hidden)]` and called only
by JavaScript. Reading `flight_recorder.rs` will not show this — `cargo expand` will.

For each of these, the old inference recognised the type as a primitive or as the impl's own type
and passed it through, whereas a projection routes it through `from_wire`/`to_wire` even when
`Wire = Self` and `Ok` is the only reachable arm. Note it is the **return** type that decides, not
the parameter list: `FlightRecorderClient::new()` takes no arguments and still gets a `Result`,
because `Self` is projected onto `<Self as ToWasm>::Wire` and `to_wire` is fallible by trait
signature.

**The `.d.ts` does not change** — wasm_bindgen renders `Result<T, E>` as `T` plus a throw, so
`infallible(n: number): number` is emitted identically either way. Checked directly against a shim
written both ways.

| Crate                                   | Methods                                                                                                                                                                                            |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `bitwarden-wasm-internal`               | `PasswordManagerClient::{echo, version, gov_mode}`, `FlightRecorderClient::{new, count}`, `PureCrypto::{make_user_key_aes256_cbc_hmac, make_user_key_xchacha20_poly1305, random_number, new_guid}` |
| `bitwarden-ipc`                         | `IncomingMessage::parse_payload_as_json`, `JsIpcClient::{new_with_sdk_in_memory_sessions, is_running}`                                                                                             |
| `bitwarden-managed-settings`            | `ManagedSettingsClient::{new, is_managed, get}`                                                                                                                                                    |
| `bitwarden-user-crypto-management`      | `PinSettingsClient::{validate_pin, get_pin}`                                                                                                                                                       |
| `bitwarden-random`                      | `SdkRandomNumberClient::{new, gen_uuid}`                                                                                                                                                           |
| `bitwarden-server-communication-config` | `JsServerCommunicationConfigClient::needs_bootstrap`                                                                                                                                               |

Plus `PinSettingsClient::unset_pin`, which takes and returns nothing. It was the last method still
using the old pass-through branch — 1 of roughly 250 shims — so that branch was deleted and every
shim is now fallible. One code path beats a second one kept alive for a single method whose
TypeScript is `void` either way.

Three things were considered and rejected:

- **Keeping the pass-through branch.** See above: one method tree-wide.
- **Special-casing the impl block's own type.** It is always a handle — `#[wasm_bindgen]` only
  accepts an impl block on a type it exports — so `Self` could skip the projection and keep every
  constructor's shim infallible. Rejected for the same reason: a second rule to keep correct, for a
  difference no consumer can observe.
- **Making `ToWasm::to_wire` infallible.** Serializing a Rust value we built ourselves is a
  programming bug rather than bad input, so a `Result` there looks like noise. But infallible means
  panicking, and a panic aborts the wasm instance — which is exactly the `into_wasm_abi` behaviour
  described in [Why](#why), and takes the whole SDK down for the session instead of letting the
  client catch an error and keep going. `bitwarden-error`'s `full` mode already made this call the
  same way, which is why `wire.rs` reuses `CONVERSION_ERROR_NAME`.

If the generated `Result` still needs to go, the lever is a macro-visible infallibility marker, not
a panic.

### `bitwarden-ipc`

The doc used to call this the hardest crate. Under the wire traits it is unremarkable, and all three
of its special cases dissolved:

- **`ts = false` is gone.** `ipc_client.rs` and `communication_backend.rs` carried it to turn
  inference off for blocks that exchange only handles. Now `JsIpcClient`, `JsIpcClientSubscription`
  and `JsCommunicationBackend` are `#[wasm_object(js_name = ..)]`, so their `Wire = Self` and the
  blocks are plain `#[wasm_export(js_class = ..)]`.
- **Struct `pub` fields are unchanged, and still need hand-writing.** `#[wasm_bindgen]` generates a
  setter per `pub` field, which the macro does not cover, so `destination` (×2) and `source` in
  `message.rs` keep `#[cfg_attr(feature = "wasm", wasm_bindgen(skip))]` with accessors written out
  in `wasm/message.rs`. Those accessors name `Ts<Endpoint>` directly, which is why `wire.rs` carries
  an identity impl for `Ts<T>` — without it `#[wasm_export]` could not project a signature that
  already holds a wire value.
- **`extern "C"` is settled.** `js_session_repository.rs` takes `endpoint: Ts<Endpoint>` in the JS
  functions we call, written by hand, with `impl_wire_object!(RawJsSessionRepository)` for the
  repository handle itself. The direction there is Rust → JS (`IntoWasmAbi`, the `panic!` path)
  rather than the leaking one.

### State bridge

`state_bridge!` is the one place a per-value annotation survives, and it is that macro's own hatch,
unrelated to `#[wasm_export]`. Five of its ten fields keep `#[ts(skip)]`: `user_key`, `user_key_id`,
`persistent_pin_envelope`, `ephemeral_pin_envelope`, `encrypted_pin`.

The reason is a genuine gap rather than laziness. The macro receives a raw `JsValue` across a
`ThreadBoundRunner` boundary and has to build the wire value from it — `Ts::<T>::new_unchecked(js)`
for a record, `T::try_from(js)` for a hand-rolled-ABI type. `FromWasm` has no "construct `Wire` from
a `JsValue`" operation, and adding one would require every `#[wasm_object]` type to implement
`TryFrom<JsValue>`, which extern types cannot. Since the bridge is documented as a temporary layer
awaiting `bitwarden-state` support for non-repository state, it was left alone.

Otherwise `bitwarden-core`'s state bridge only needed `impl_wire_object!(RawWasmStateBridge)` and
one import re-gated (see below); `bitwarden-state` itself needed nothing but the dependency.

## Things that cost time, so you do not rediscover them

- **`bitwarden-error`'s `basic` and `flat` modes never used tsify.** They hand-write
  `From<E> for JsValue` via `SdkJsError`. Only `full` mode needed changing.
- **`full` mode does not require `Display`.** `crates/bitwarden-error/tests/full.rs` uses it on an
  enum without `thiserror`, despite what `bitwarden-error-macro/CLAUDE.md` claims. The serialization
  fallback therefore cannot use `error.to_string()`.
- **Struct fields are a leak path no macro covers.** `#[wasm_bindgen]` generates a setter per `pub`
  field, so `pub destination: Endpoint` on `OutgoingMessage` leaks the same way. See
  [bitwarden-ipc](#bitwarden-ipc). Another one cannot appear unnoticed — it would not compile once
  `Endpoint`/`Source` lose their attributes.
- **`cargo fix` will delete imports that only `target_arch = "wasm32"` code uses.** It runs against
  the host target, so it cannot see inside those blocks. It removed
  `#[cfg(feature = "wasm")] use wasm_bindgen::prelude::*;` from
  `crates/bitwarden-core/src/key_management/state_bridge.rs`, which left the host build clean and
  broke the wasm32 build with 45 cascading errors — `wasm_bindgen` not resolving as an attribute
  meant `extern "C" { pub type RawWasmStateBridge; }` was parsed as a real extern type, so the
  errors read `extern blocks must be unsafe` and `extern types are experimental` and pointed nowhere
  near the cause. It is now `#[cfg(target_arch = "wasm32")]`, matching its only remaining use. After
  any `cargo fix` sweep, build for wasm32 before believing it.
- **`dylint` can fail locally** with
  `Could not find libbitwarden_lints@<toolchain>.dylib despite successful build`, chasing a
  toolchain other than the pinned `nightly-channel`. Unrelated to this work; confirm against `main`
  before chasing it.
- **Do not run cargo and an unsandboxed `npm run lint` concurrently.** They share a target directory
  but not a toolchain, and the mixed proc-macro artifacts surface as nonsense expansion errors
  (`const items in this context need a name`, `can't use Self from outer item`) in whichever crate
  uses `#[wasm_export]` next. `cargo clean -p bitwarden-ffi-macro` clears it.
