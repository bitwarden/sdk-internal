# `#[wasm_export]` follow-ups

Deferred work on the wire-trait design landed alongside
[TSIFY_TS_MIGRATION.md](./TSIFY_TS_MIGRATION.md). Read that first — it explains `FromWasm`/`ToWasm`,
the three macros, and the phase plan. Delete this file when the list is empty.

Nothing here blocks the migration. The tree compiles, tests pass, and the generated `.d.ts` matches
`main`.

## Test gaps

- **No compile-fail coverage for the macros' error paths.** `bitwarden-ffi/tests/compilation_tests/`
  has one trybuild case (`unknown_wasm_only_attribute`). Unexercised paths, each of which returns a
  `compile_error!` today:
  - `#[wasm_record]` with any argument (it takes none).
  - `#[wasm_record]` / `#[wasm_object]` on a generic type.
  - `#[wasm_record]` / `#[wasm_object]` on something that is not a struct or enum.
  - `#[wasm_object]` with an unparseable argument list.
  - `#[wasm_export]` on a generic impl block, generic method, or generic free function. Only the
    impl-block case has a unit test asserting the message.
- **The `Ts<T>` identity impl has no direct test.** `impl FromWasm for Ts<T>` /
  `impl ToWasm for Ts<T>` in `wire.rs` exist so a hand-written signature can name the wire type and
  still be projected — `bitwarden-ipc`'s `wasm/message.rs` accessors are the only consumer. Nothing
  fails if it is deleted except that crate, and nothing explains why it is there. Add a case to
  `bitwarden-ffi/tests/wasm_export.rs` with a method taking and returning `Ts<Point>`.
- **No test that a record and an object cross correctly in the same call.** `Canvas::with_handle`
  covers the signature shape via a function-pointer coercion, but nothing round-trips real values
  through both kinds in one wasm call.
- **`bitwarden-uniffi` and `bw` are only checked, not exercised.**
  `cargo check -p bitwarden-uniffi -p bw` proves the Rust-facing signatures did not move, which is
  the point of the second impl block, but no test calls a migrated method through UniFFI.

## `state_bridge!` still needs `#[ts(skip)]`

Five of the ten fields in `crates/bitwarden-core/src/key_management/state_bridge.rs` carry
`#[ts(skip)]`: `user_key`, `user_key_id`, `persistent_pin_envelope`, `ephemeral_pin_envelope`,
`encrypted_pin`. This is `bitwarden-state-bridge-macro`'s own hatch, unrelated to `#[wasm_export]`,
and it is the only per-value annotation left in the tree.

**Why it cannot just use the traits.** The macro receives a raw `JsValue` across a
`ThreadBoundRunner` boundary and has to build the wire value from it:

```rust
// record:            Ts::<T>::new_unchecked(js).to_rust()
// hand-rolled ABI:   T::try_from(js)
```

`FromWasm` has no "construct `Wire` from a `JsValue`" operation, so the macro cannot express both
uniformly. Adding one would require every `#[wasm_object]` type to implement `TryFrom<JsValue>`,
which the `extern "C"` handle types cannot.

**Options, roughly in order of preference:**

1. **Leave it.** The bridge's own module docs call it a temporary layer to be replaced by
   `bitwarden-state` once that supports non-repository state. Removing the hatch has no value if the
   whole macro goes away.
2. **Add a `wire_from_js` method with a default that only records can satisfy**, and keep `bare` for
   the rest. Smaller hatch, same shape.
3. **Give the bridge a `Ts`-typed channel** so the `JsValue` never appears, and the wire traits
   apply directly. Largest change, touches `ThreadBoundRunner` usage.

Whatever happens, `bitwarden-state` itself needs nothing — only the `bitwarden-ffi` dependency,
which it already has.

## Absorb the UniFFI derives into `#[wasm_record]`

Wanted, but **not yet** — deliberately out of scope for this migration.

Today a DTO carries a stack of attributes that always appear together:

```rust
#[wasm_record]
#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(rename_all = "camelCase")]
pub struct CipherView { .. }
```

`#[wasm_record]` could emit the serde and UniFFI derives too, collapsing that to one attribute and
giving a single place to change if either binding layer moves. The reason to wait: it puts
`bitwarden-ffi-macro` in front of UniFFI as well as wasm, which is a broader ownership decision than
"stop leaking on bad input", and it would need `uniffi::Enum` versus `uniffi::Record` handling that
the wasm side does not care about. Worth revisiting once the phase plan has landed.

## Unrelated, but noticed

- **`dylint` fails locally** with
  `Could not find libbitwarden_lints@<toolchain>.dylib despite successful build`, chasing a
  toolchain other than the pinned `nightly-channel`. Confirm against `main` before investigating; it
  is not caused by this work.
