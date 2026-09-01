# SDK runtime introspection — design

Status: sketch / early draft
Date: 2026-09-01
Owner: Andreas Coroiu

## Goal

Give automated dev tooling (a Claude agent) live read and controlled write
access to SDK state during development and troubleshooting, to compensate for
the lack of a usable debugger when the SDK runs on WASM. The whole surface is
behind `#[cfg(feature = "introspect")]` and absent from release builds, so it
ships no runtime cost and no attack surface.

## Why not "just reflect"

Rust has no runtime reflection: there is no global registry of live objects and
no way to enumerate a struct's fields generically. So introspection must be
**opt-in per type** (a derive) and **rooted** — walked from a reference we hold,
which in this SDK is the `Client` (`bitwarden-core`, owns everything via
`Arc<InternalClient>`). This is a structured state-inspection surface, not a
general debugger.

## Discovery model — lazy, path-addressed

`Introspect` exposes a node model. At any node:

- `node_info()` returns a `NodeInfo` snapshot: `type_name`, a cheap `preview`,
  a `Writeability` descriptor, and the list of child edges (`ChildRef`).
- `describe(path)` descends one segment at a time (`vault.ciphers[3].name`),
  returning owned snapshots rather than borrows — so lock-guarded nodes are read
  under a guard that lives only for the call, never handed out.

Chosen over an eager whole-`Client` dump because real state is large and the bug
location is unknown; crawling only materializes the path being walked.

## Writing — three sound tiers, no `unsafe`

Reaching a node happens through shared references, and Rust does not allow
mutation through `&T`. Each tier answers "where does exclusive access come
from":

1. **`CloneReplace` (default).** Take the write lock on the nearest lock-guarded
   ancestor, clone the target, apply the change, store it back. Reaches
   arbitrary leaves. Requires `Clone` + a lock-guarded ancestor.
2. **`InPlace` via `Debuggable<T>` (surgical opt-in).** `#[repr(transparent)]`
   over `T` in release-shaped builds (zero cost); `RwLock<T>` under the
   `introspect` feature, with a uniform `get()`/`set()`/`From` surface so
   constructors and (future) serde don't churn. This is the only tier whose
   writes are visible to other live references to the same value. Developers
   wrap fields as they go during normal development.
3. **Documented manual escape hatch.** For the residual (non-`Clone`, unguarded)
   leaves: a hands-on utility plus docs teaching the agent when tiers 1–2 can't
   reach and what the manual move is.

Rejected alternatives (both sound Rust, both wrong trade here): a macro that
makes every field writable transparently (transparency + write-through-`&` are
mutually exclusive), and a global arena/handle store (re-architects the whole
model and reintroduces process-global mutable state the design deliberately
avoids, for no capability gain over `CloneReplace`).

## Transport — v1 follows the automation-driver

Bernd's automation-driver PRs (bitwarden/clients #21921/#21922) already provide
a transport and a Claude-skills framework: an `AutomationDriver` attached to the
JS global (`window.bitwardenAutomationDriver`), driven over the Chrome DevTools
Protocol via `chrome-devtools-mcp`, with per-capability skills. Its `logging`
capability already crosses into the WASM SDK (`FlightRecorder.read()`), proving
the pattern.

**v1 decision: follow that lead.** Expose the introspection surface through
`bitwarden-wasm-internal` as a new automation-driver capability
(`window.bitwardenAutomationDriver.sdkIntrospect.describe(path)` /
`.set(path, value)`), mirroring how `flightRecorder` is wired, and add one skill
reference doc. This reuses his transport and skills wholesale; we build the Rust
side plus a thin JS capability shim.

- Complementary layers: his driver reads serialized storage JSON (vault stays
  encrypted) and drives the UI; ours reads the live, decrypted in-memory SDK
  object graph — the gap he can't reach.
- Name ours distinctly (`sdkIntrospect`) to avoid confusion with his `state`
  capability.

## Transport — known future constraints (design for, don't build yet)

The SDK's direction of travel is toward native Rust hosts, which the CDP path
does not cover:

- Desktop `Client` is moving from the renderer into **Node (main process)** for
  native memory protections. CDP attaches to the renderer only; the Node host is
  reached via the V8 Inspector (a CDP dialect) or an Electron IPC bridge. No
  bespoke Bitwarden bridge is required if we attach to the process that hosts
  the `Client`.
- The **CLI is becoming Rust-native** — no JS runtime, no inspector at all.
- Mobile (uniffi) likewise has no inspector.

Implication: keep the **Rust introspection core transport-neutral** (it already
is — it just answers `describe(path)` with serializable data). A native adapter,
plausibly over the existing `bitwarden-ipc` crate, is the planned follow-up for
CLI/mobile/Node. Not built in v1 (YAGNI), but the core boundary stays clean so
it slots in without rework. `bitwarden-ipc`'s suitability is unverified and
should be confirmed before that adapter is designed.

## Crates

- `bitwarden-introspect` — the `Introspect` trait, `NodeInfo`/`ChildRef`/
  `Writeability`, leaf/`Vec`/`Option` impls, and `Debuggable<T>`.
- `bitwarden-introspect-macro` — `#[derive(Introspect)]` and the
  `#[introspect(skip | writable)]` field attributes.

The existing client macro can additionally auto-wire the `Client` root.

## Open items / not yet built

- Path-addressed **writing** dispatch in the derive (the read/discovery path and
  the `Debuggable` mechanism are sketched; `set(path, value)` routing is not).
- **Serialization** of `NodeInfo` for the wire (serde), and the wasm-bindgen
  capability shim onto `window.bitwardenAutomationDriver`.
- Enum, tuple-struct, and generic-bound handling in the derive.
- Cycle/`Arc` handling: depth limit + visited-set for the real object graph.
- Coordinate with Bernd: #21922 is draft; his capability layout and the
  `attachToGlobalIfDev`-vs-"all builds" gating decision shape where our surface
  hangs and whether it must be feature-gated on both the Rust and TS sides.
