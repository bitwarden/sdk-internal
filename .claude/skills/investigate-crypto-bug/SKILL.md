---
name: investigate-crypto-bug
description:
  Investigate a cryptography bug report (decryption failures, wrong keys, unlock failures, MAC
  errors, corrupted EncStrings, key rotation/migration issues). Use when the user provides evidence
  (logs, error messages, stack traces, bug tickets) of a crypto misbehavior and asks to
  "investigate", "find the root cause", or "reproduce" it. Traces code paths back from each evidence
  point to form theories, then proves or disproves each with a failing integration test.
model: opus
---

# Investigate a crypto bug

Two phases. Do not skip to fixing. The deliverable is **verified theories + a reproducing test**,
not a patch.

```
evidence ──► trace back ──► theories ──► reproducing test ──► verdict per theory
   ▲                                          │
   └────── add log statements, re-run ◄───────┘
```

## Phase 1 — Theories

### 1.1 Collect evidence points

List every concrete piece of input: log lines, error variants/messages, stack traces, client
version, platform (web/desktop/mobile), account state (KDF, encryption type, org membership, key
connector, V1/V2 user), and the user action that triggered it. If a Jira ticket is referenced, read
it and its comments with the Atlassian tools.

Number the evidence points (E1, E2, …) so theories can cite them.

### 1.2 Locate each evidence point in code

For each evidence point, find the exact line that emits it (grep the log message / error variant /
`#[error(...)]` string). Record `file:line`. If a message could come from several places, list all
candidates and note which the evidence rules out.

### 1.3 Trace backwards

From each emission point, walk callers upward to the entry point (WASM/UniFFI binding → feature
client → core / crypto). For each hop note:

- **Known values**: a log line pins the values at that point (key type, `EncString` variant, key id,
  KDF params, state flags). Anything a log proves is fact, not assumption.
- **Branches taken**: which conditions must have held to reach this line.
- **Inputs**: where each value came from — server response, local state, `KeyStore`, derived,
  migrated, cached.

Then for each evidence point ask:

- **Values unexpected** -> what sequence of conditions produced them? Walk back to where the value
  was set/derived/loaded and enumerate the ways it could have been set wrong (stale state, wrong key
  id, wrong key selected, format mismatch, legacy vs. new encryption type, race between
  lock/unlock/sync, partial migration, server returning different data).
- **Values expected** -> the bug is downstream. Where after this point could the unexpected behavior
  be introduced? Follow the forward path to the failure.

Things that commonly matter in this SDK:

- Which key decrypted what: user key vs. org key vs. cipher key vs. legacy master key.
- `EncString` / encryption type (AES-CBC-HMAC vs. COSE / XAES-GCM) and backward compatibility with
  data from older releases.
- `KeyStore` context lifetime — contexts held across `await`, keys set in one context and read in
  another.
- State load order: sync vs. unlock vs. key-connector / TDE / PIN / biometrics paths.
- FFI conversion (WASM / UniFFI) mangling a value between the client and Rust.

Use `Explore` agents in parallel for broad caller sweeps across crates; read the critical code
yourself.

### 1.4 Output the theories

Present to the user before Phase 2:

```
Theory T1: <one sentence: what goes wrong and why>
  Evidence:    E1, E3 (explains), E2 (consistent with)
  Path:        crates/.../a.rs:120 → crates/.../b.rs:45 → …
  Preconditions: <state/input needed to trigger>
  Contradicted by: <evidence that argues against, or "none">
  Verify by:   <what the test must set up and assert>
```

Rank by how much evidence each explains. Discard theories contradicted by a log; say why.

## Phase 2 — Reproduce

### 2.1 Pick the harness

Prefer, in order:

1. **Shared unlock Rust test** — for shared unlock bugs only; preferred over WASM there.
   `crates/bitwarden-shared-unlock/tests/`: `harness/` simulates devices running real
   `SharedUnlockPeer`s over an in-memory IPC transport with real Noise sessions; `scenarios/` holds
   topologies (simple, tree, V-shaped), restarts, peer loss, client quirks — copy the closest one.
   Read `harness/mod.rs` docs first (fast timings, `RUST_LOG` capture). Run:
   `cargo test -p bitwarden-shared-unlock --test shared_unlock <filter>`.
2. **WASM integration test** (Jest) in `crates/bitwarden-wasm-internal/integration-tests/`. Read its
   `Readme.md` first. Building blocks:
   - `test-harness.ts` — `testHarness()` gives a `ServerEmulator` (fetch hooked) and
     `newClientEmulator()`. Call `restore()` in `afterEach`.
   - `server-emulator/` — backend model. **Seed state through the server and sync**; never write
     client state or bridges directly, and never mock individual routes.
   - `client-emulator/` — platform services / local state.
   - `vectors/` + repo-root `test-vectors/` — recorded accounts for every crypto version.
     `testVectors.eachUser()` / `eachUserAndUnlockMethod()` run one body against all of them — use
     this when the bug may depend on account crypto version.
   - Existing tests under `tests/` (e.g. `unlock/`, `user-crypto-management/`, `crypto/`) — copy the
     closest one.
3. **Rust integration test** (`crates/<crate>/tests/`) only when the path is not reachable through
   the WASM surface, or the bug is below the bindings and a WASM test adds nothing.

If no existing harness can express the scenario, **stop and ask the user** before building a new
harness. Small extensions to the server/client emulator (a missing route or field that the real
server has) are fine; say what you added.

### 2.2 Write the test

- One test per theory, named after the correct behavior
  (`"decrypts org cipher after key rotation"`), not the bug.
- Assert the **correct** behavior: the test fails while the bug exists and passes once fixed.
- Reproduce the preconditions from the theory as faithfully as the evidence allows (same account
  type, same order of operations).
- Use test keys and test vectors only — never real keys or vault data.

### 2.3 Run it

WASM:

```sh
cd crates/bitwarden-wasm-internal/integration-tests
npm run build:test          # rebuilds wasm (build.sh) then runs jest
npm run test -- -t "<name>" # re-run without rebuilding when only TS changed
```

Rust:

```sh
cargo test -p <crate> --all-features --test <file> <filter> -- --nocapture
```

Rebuild the wasm after every Rust change, including added log statements.

### 2.4 Instrument when the result is ambiguous

If the test fails for a different reason than the theory predicts, or passes unexpectedly:

- Add temporary `tracing::debug!`/`info!` statements at the hops from 1.3 that distinguish the
  theories (which key id, which branch, which encryption type). Log identifiers and types, **never
  key material or plaintext**.
- For WASM, call `init_sdk(LogLevel.Debug)` in the test so they reach the console.
- Re-run, compare against the theory's predicted values, update or discard the theory, and loop.

Mark every temporary log statement (e.g. `// TEMP investigate`) and remove them all before
finishing.

### 2.5 Report

```
T1: CONFIRMED | DISPROVEN | INCONCLUSIVE
  Test:   <path>::<name> — fails with <actual error/assertion>
  Proof:  <log/assertion output that settles it>
```

List remaining open questions. Do not write the fix unless asked; when the fix comes, the
reproducing test is its regression test.

## Rules

- Evidence beats intuition: a theory contradicted by a log is dead.
- Never change committed test vectors to make a test pass — a vector that stops decrypting is a real
  backward-compatibility break.
- Ask before building a new harness.
- Remove all temporary instrumentation before handing back.
