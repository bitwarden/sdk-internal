# Integration Tests

This is a set of integration tests for the sdk. This aims to find issues that unit tests do not
uncover, and especially find issues where the FFI conversions are broken.

## The four kinds of test

We have a few different test kinds, with different intents.

### `happy-path.test.ts`

Basic functionality against the committed test vectors. Does the feature work at all, for the
recorded data. Every feature should have these.

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
`tests/model-server/sync.ts` provides the helpers: `syncToLocalState`, `validateAfterLockUnlock`
(lock → unlock, no sync) and `validateAfterLogoutLogin` (discard local state, sync, unlock).

### `conformance.test.ts`

Low-level. Asserts the state **before and after**, and asserts implementation detail — what is in
local state, which routes were called, what the stored ciphertext looks like, what shape went on the
wire.

**These will break often**, and that is the point: they are the ones that pin down exactly what the
SDK does, so a behavioural change cannot slip through unnoticed. When one breaks, the question is
"did we mean to change this?" — not "how do I make it pass again". Maximum correctness, deliberately
at the cost of churn. Use this where necessary.

This is the one kind that may read request bodies and assert route sequences

### `edge-cases.test.ts`

Interesting cases or bugs we want to prevent regression of.
