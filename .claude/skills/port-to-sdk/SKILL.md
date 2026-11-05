---
name: port-to-sdk
description:
  Port a feature from an origin app (TS clients, Android, or iOS) into the SDK and replace the
  origin implementation with SDK calls. Use when asked to "port X to the SDK", "move X into the
  SDK", or "replace X in clients/android/ios with the SDK". Classifies the port, picks a rollout
  (feature flag or direct), and delivers draft PRs with unit, SDK e2e, and origin e2e tests.
---

# Port to SDK

```
 0 Source ─▶ 1 Gather ─▶ 2 Rollout ─▶ 3 Build + test ─▶ 4 Draft PRs
 (ask)       behavior     flag/direct   SDK, then origin   SDK PR + origin PR
```

## 0. Source

Origin is one of `clients`, `android`, `ios`. If the prompt does not name it, ask with
`AskUserQuestion`. Also ask for the Jira ticket(s) if none are given.

## 1. Gather behavior

Read the origin **implementation and its unit tests**. The tests are the behavior spec; every
`it`/`@Test`/`func test` becomes a row in the inventory. Skim the other two platforms for the same
feature: divergent behavior must be resolved before porting, not copied.

Produce, in a short report:

1. **Inventory** — public methods, branches, error paths, side effects (events, toasts, logs).
2. **Dependencies** — tag each method: `crypto`, `api`, `state` (repository id→record, or
   singleton), `platform` (secure storage, biometrics, IPC, push, UI).
3. **SDK coverage** — `git grep` the crates. Per method: exists+exposed / exists-not-exposed /
   partial / absent. Port only the gap.
4. **Category** — pick one from [references/categories.md](references/categories.md). It decides
   reference implementation, new infra, and test layers.
5. **New infra** — API bindings (generated; regenerate, never hand-write), state bridge entries
   (KM-owned, ask first), repositories, platform callback traits, new crate/sub-client.

Stop and confirm the report and the proposed public interface (Rust signatures + one origin call
site) with the user. Interface rules: domain types, one call per user intent, enums over booleans,
typed IDs, request/response structs, minimal `pub` surface. Same shape on WASM and UniFFI.

## 2. Rollout

Default to **side-by-side behind a feature flag**. Direct port only when all hold:

- pure function, no `state` or `api` dependency;
- SDK result is byte-identical to the origin (pinned by a test vector);
- trivially revertible.

Flag-gated: keep the origin abstraction, add an SDK-backed implementation, select by flag (clients
examples in [references/categories.md](references/categories.md)). Flag naming and lifecycle:
`bitwarden-delivery-tools:managing-feature-flags`. Both paths must pass the same tests. Removing the
old path is a follow-up PR after rollout.

State written by the SDK path must stay readable by the old path (same storage key and format), so
toggling the flag off never loses data.

## 3. Build and test

Order: SDK first, then origin. The origin PR depends on an SDK release; note the required version.

**Unit** — port every origin unit test to a Rust `#[cfg(test)]` test; no behavior row without one.
Origin unit tests cover the flag selection and the SDK adapter.

**SDK e2e** — use the `writing-e2e-tests` skill. Cover every public method, branch and error variant
through the built package. Add server emulator routes and test-vector fields as needed.

**Origin e2e**:

| Origin    | Framework         | Action                                         |
| --------- | ----------------- | ---------------------------------------------- |
| `clients` | Playwright `e2e/` | Add tests via `writing-end-to-end-tests` skill |
| `android` | none              | Do not add a framework; label PR `needs-qa`    |
| `ios`     | none              | Do not add a framework; label PR `needs-qa`    |

Re-check before labeling: a framework may have landed since. If an origin e2e test needs
infrastructure the suite lacks (SSO IdP, second device), say so in the PR and add `needs-qa`.

Before the SDK is published, test the origin against the local build: clients — point
`node_modules/@bitwarden/sdk-internal` at `crates/bitwarden-wasm-internal/npm` after `build.sh`
(needs `rust-src` for the pinned toolchain). Type errors from version skew are not yours; filter by
touched files.

Verify before claiming done: `cargo test -p <crate> --all-features`, `npm run lint`, SDK e2e suite,
origin unit tests, origin e2e tests. Report anything not run.

## 4. Draft PRs

One SDK PR, one origin PR, each on its own branch, opened with `gh pr create --draft`. Title
`[PM-XXXXX] <type>: <subject>`. Body, nothing more:

```
## Tickets
- [PM-XXXXX](https://bitwarden.atlassian.net/browse/PM-XXXXX)

## What
<one or two lines>

## Rollout
Behind `<flag>` | Direct

## Depends on
<SDK PR link / version>   (origin PR only)
```

If the user says not to push, stop at local branches and report their names.

## Guardrails

- Zero-knowledge: keys stay in the `KeyStore`; never return raw keys or log protected data.
- Origin code calls SDK sub-clients only, never the state bridge or repositories directly.
- Do not widen existing visibility (`pub(crate)` → `pub`) without asking.
- Do not port origin rough edges (nullable soup, boolean params, multi-step call sequences).
