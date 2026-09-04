---
paths:
  - "crates/bitwarden-wasm-internal/integration-tests/**"
---

# Integration tests

These tests drive the real WASM SDK against an in-memory model of the backend
(`tests/model-server/`). The conventions below are not style preferences: each exists because its
absence produced a test that passed while proving nothing.

## Assert on state, never on what the client sent

- **Never inspect a request body.** No `bodyFor`, no `request.body`. A body shows what the client
  intended; the stored account shows what a user has to live with afterwards.
- **Never assert that a route was called.** No `servers.called`, and no route-sequence assertions
  where state already covers the outcome.
- If something is _only_ observable from which route was hit, **model the constraint on the server**
  so a wrong call fails by itself. Push checks into the model, not into every test.
- Secrets on the wire are policed centrally — the server inspects every request for any seeded
  account's password, user key, private key or master key. Assert `api.secretLeaks()` is empty in
  `afterEach`; do not spot-check bodies.

The exceptions are `conformance.test.ts`, whose subject is the wire shape itself, and
`tests/model-server/model-server.test.ts`, whose job is to prove the harness's own mechanisms fire.

## Every mutation is validated from both directions

A write has to leave two things working, and they fail independently, so assert both:

```ts
// Lock → unlock: the writing client's own local state must still open. No sync.
await validateAfterLockUnlock(local, unlockMethodFor(api, email), expected);
// Logout → login: discard local state, sync from the server, unlock from nothing else.
await validateAfterLogoutLogin(api, email, expected);
```

**Order matters.** Lock/unlock comes first because syncing would overwrite the thing it checks. A
write that posts a correct account but fails to persist locally is invisible to a sync-first
assertion — that is the case the split exists for, and it is worth re-proving if either helper is
ever changed.

The client that performed the write is not evidence on its own: it holds values from its own
response. Never reuse a state bridge across generations either — one carrying the previous user key
can let an unlock succeed by reading it back instead of deriving it.

## Arrange, act, assert — and assert is usually one call

```ts
it("keeps a cipher decryptable after an edit", async () => {
  // Arrange
  const { client, assertAccountIntact } = await arrange(account);

  // Act
  await client.vault().ciphers().edit(renameRequest(before, "edited"));

  // Assert
  await assertAccountIntact({ expect: { ciphers: { [item.id]: { name: "edited" } } } });
});
```

Use the validator's `expect` option to declare what the act step deliberately changed, rather than
dropping back into hand-written comparisons. Only claims specific to a test's own intent are written
out beside it — a rejection, a removal from both sides. "The account is still coherent" belongs in
the validator.

## Two helpers and one local state

- `LocalState` (`tests/model-server/local-state.ts`) owns the state bridge and the client-managed
  repositories together, with `seedAccount` / `seedVault` for seeding.
- `syncToLocalState(api, email, local)` copies an account out of the server — keys into the bridge,
  vault into the repositories — exactly as a real sync does. Must be idempotent.
- `validateLocalState` unlocks and decrypts **everything the repositories hold**, comparing to the
  recorded plaintext. Decrypt what local state holds, never the vector's own copies: after a write
  those are re-encrypted, and that is the whole point.

Address accounts by **email**, resolved from the database. Do not thread an account fixture through
to the unlock call — `seedUser` returns the email, and everything needed to bring the account up is
read back out of the db.

## Assertions

- **Compare whole values.** If a re-read or a stored item is available, assert equality against it.
  A field-by-field check passes against a read that silently dropped anything it did not name.
- **Never `toBeDefined()` followed by an assertion on the same value.** Assert the value. If the
  check is a guard before dereferencing, write it as a guard (`if (x === undefined) throw …`) so
  there is no `!` afterwards either.
- **Do not assert implementation details.** A fresh IV, a particular ciphertext shape, an internal
  call order: assert the observable behaviour instead — that the plaintext round-trips.
- **Extract a helper rather than repeating manual conversions.** Branding an id, fetching from local
  state, null-checking and re-unlocking is one helper, not six lines in every test.

## Types

- **No `as never` and no `as unknown`**, in test bodies or in the harness. `as never` switches off
  checking entirely; moving it into a helper file only hides it.
- The SDK's ids and ciphertexts are opaque brands (`Tagged<Uuid, "CipherId">`) and deliberately not
  string subtypes, so a plain string cannot be cast to one directly. Convert through
  `tests/type-assertion-helpers.ts` (`asCipherId`, `asUserId`, `asEncString`, …) — one named,
  greppable place holding the single cast.
- Type request and response bodies with the DTOs in `tests/model-server/dto.ts`. A handler taking
  `any` can drop a field on the way out and still pass, which is the bug class this suite exists to
  catch.
- `npm test` runs `tsc --noEmit` first. A type error fails the suite.

## Comments

Describe **what the file contains and how its tests are shaped**. Do not justify the file's
existence or argue about what used to be uncovered — that is changelog, not documentation, and it
goes stale.

## Prove a test can fail

Before trusting a new assertion, break the thing it covers and confirm it fails. Most of the rules
above exist because an assertion that looked thorough turned out to be vacuous — a spot-check that
matched anything, an override that excused the value it was meant to check, a route table that
echoed back whatever it was sent.
