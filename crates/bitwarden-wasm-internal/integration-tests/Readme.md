# Integration Tests

This is a set of integration tests for the sdk. This aims to find issues that unit tests do not
uncover, and especially find issues where the FFI conversions are broken.

## Running them

The suite consumes the WASM package as `file:../npm`, so it has to be built first:

```sh
../build.sh          # omit -r; see below
npm ci
npm test             # tsc --noEmit, then jest
```

Build **without** `-r`. Release sets `codegen-units = 1`, which masks TypeScript aliases that
`wasm-ld` drops in debug — so a release-only build can be green in CI while the debug build the
suite actually runs against is broken.

## The model server

`tests/model-server/` is an in-memory model of the backend. A test seeds accounts into it, installs
its routes over `globalThis.fetch`, and then asserts on what the server ends up holding.

- `entities.ts` / `database.ts` — the rows, and storage indexed by owner.
- `dto.ts` — the wire shapes, one interface per request and response body.
- `serializers.ts` — DTO ↔ encrypted domain model.
- `api-server.ts` — the routes, the stale-write rule, and the secret inspector.
- `local-state.ts` — the client side: the state bridge and the client-managed repositories.
- `install.ts` — binds the routes to an origin and patches `fetch`.
- `validate.ts` — `syncToLocalState`, `unlockMethodFor`, and the two validators.
- `model-server.test.ts` — proves the harness's own mechanisms fire.

Conventions for writing tests against it are in `.claude/rules/integration-tests.md`.

## The four kinds of test

We have a few different test kinds, with different intents.

### `happy-path.test.ts`

Basic functionality against the committed test data. Does the feature work at all, for the recorded
data. Every feature should have these.

### `user-facing-flow.test.ts`

How a consumer actually uses the feature: register, unlock, edit an item, lock, unlock again, log
out, log back in.

**Do not assert state directly and do not assert sync calls.** Perform the operations a user would,
then check the three things a user can actually observe:

1. the **server's synced state** — what a returning client would be given;
2. the **local state** — what this client persisted;
3. the **post-operation state of the still-unlocked SDK** — that the client that did the work
   carries on working.

These should be stable across refactors. If one breaks, something a user relies on has changed.
`tests/model-server/validate.ts` provides the helpers: `syncToLocalState`, `validateAfterLockUnlock`
(lock → unlock, no sync) and `validateAfterLogoutLogin` (discard local state, sync, unlock).

### `conformance.test.ts`

Low-level. Asserts the state **before and after**, and asserts implementation detail — what is in
local state, what the stored ciphertext looks like, what shape went on the wire.

**These will break often**, and that is the point: they are the ones that pin down exactly what the
SDK does, so a behavioural change cannot slip through unnoticed. When one breaks, the question is
"did we mean to change this?" — not "how do I make it pass again". Maximum correctness, deliberately
at the cost of churn. Use this where necessary.

This is the one kind that may read request bodies.

### `edge-cases.test.ts`

Interesting cases or bugs we want to prevent regression of.
