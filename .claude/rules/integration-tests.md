---
paths:
  - "crates/bitwarden-wasm-internal/integration-tests/**"
---

# Integration tests

These tests drive the real WASM SDK against an in-memory model of the backend
(`tests/model-server/`) seeded from the committed vectors in `/test-vectors`. The conventions below
are not style preferences: each exists because its absence produced a test that passed while proving
nothing.

## Assert on state, never on what the client sent

- **Never inspect a request body.** No `bodyFor`, no `request.body`. A body shows what the client
  intended; the stored account shows what a user has to live with afterwards.
- **Never assert that a route was called.** No `servers.called`, and no route-sequence assertions
  where state already covers the outcome.
- If something is _only_ observable from which route was hit, **model the constraint on the server**
  so a wrong call fails by itself. The key connector does this: `POST` with a key present returns
  409, `PUT` with none returns 404, so a client that picks the wrong verb fails the operation and no
  test has to look. Push checks into the model, not into every test.
- Secrets on the wire are policed centrally — the server inspects every request for any seeded
  account's password, user key, private key or master key. Assert `api.secretLeaks()` is empty in
  `afterEach`; do not spot-check bodies.

The one exception: `tests/model-server/model-server.test.ts` may build requests by hand, because its
job is to prove the harness's own mechanisms still fire.

## Every mutation is validated from both directions

A write has to leave two things working, and they fail independently, so assert both:

```ts
// Lock → unlock: the writing client's own local state must still open. No sync.
await validateAfterLockUnlock(local, unlockMethodFor(api, email), vector, options);
// Logout → login: discard local state, sync from the server, unlock from nothing else.
await validateAfterLogoutLogin(api, email, vector, options);
```

**Order matters.** Lock/unlock comes first because syncing would overwrite the thing it checks. A
write that posts a correct account but fails to persist locally is invisible to a sync-first
assertion — that is the case the split exists for, and it is worth re-proving if either helper is
ever changed.

The client that performed the write is not evidence on its own: it holds values from its own
response. Never reuse a state bridge across generations either — one carrying the previous user key
can let an unlock succeed by reading it back instead of deriving it.

Rotation is the exception: with `upgrade_token_action: "Skip"` a rotation deliberately writes
nothing to local state, so the writing client is _expected_ to be left stale. Those tests assert
logout/login only, and say so in a comment.

## Arrange, act, assert — and assert is usually one call

```ts
it("keeps a blob cipher decryptable after an edit", async () => {
  // Arrange
  const client = await arrange(vector);

  // Act
  await client.vault().ciphers().edit(renameRequest(before, "edited"));

  // Assert
  await assertAccountIntact({ expect: { ciphers: { [item.id]: { name: "edited" } } } });
});
```

Use `validateVector`'s `expect` option to declare what the act step deliberately changed, rather
than dropping back into hand-written comparisons. Only claims specific to a test's own intent are
written out beside it — a rejection, a removal from both sides, an attachment key surviving. "The
account is still coherent" belongs in the validator.

## Two helpers and one local state

- `LocalState` (`tests/model-server/local-state.ts`) owns the memory state bridge and the memory
  repositories together, with `seedAccount` / `seedVault` for seeding.
- `syncToLocalState(api, email, local)` copies an account out of the server — keys into the bridge,
  vault into the repositories — exactly as a real sync does. Must be idempotent.
- `validateLocalState` / `validateVector` unlock and decrypt **everything the repositories hold**,
  comparing to the recorded plaintext. Decrypt what local state holds, never the vector's own
  copies: after a write those are re-encrypted, and that is the whole point.

Address accounts by **email**, resolved from the database. Do not thread a vector through to the
unlock call — `seedUser` returns the email, and everything needed to bring the account up is read
back out of the db.

## Assertions

- **Compare whole values.** If a re-read or a stored item is available, assert equality against it.
  A field-by-field check passes against a read that silently dropped anything it did not name.
- **Never `toBeDefined()` followed by an assertion on the same value.** Assert the value. If the
  check is a guard before dereferencing, write it as a guard (`if (x === undefined) throw …`) so
  there is no `!` afterwards either.
- **Do not assert implementation details.** A fresh IV, a particular ciphertext shape, an internal
  call order: assert the observable behaviour instead — that the plaintext round-trips.
- **Extract a helper rather than repeating manual conversions.** Branding an id, fetching from local
  state, null-checking, stringifying to check for plaintext, re-unlocking and comparing is one
  helper (`expectCipherFromServer`), not six lines in every test.

## Types

- **No `as never` and no `as unknown`** in test bodies. `as never` switches off checking entirely.
- The SDK's ids and ciphertexts are opaque brands (`Tagged<Uuid, "CipherId">`) and deliberately not
  string subtypes, so a plain string cannot be cast to one directly. Convert through
  `tests/type-assertion-helpers.ts` (`asCipherId`, `asUserId`, `asEncString`, …) — one named,
  greppable place.
- Type request objects with the SDK's own interfaces
  (`satisfies UserMasterPasswordRegistrationRequest`). It catches missing fields; a blanket cast
  hides them.
- `npm test` runs `tsc --noEmit` first. A type error fails the suite.

## Exercise the real path, not a value you already hold

Where an operation spans two servers, unlock the way a client actually would. After migrating to key
connector, log in with the **URL** (`keyConnectorUrl`), so the SDK fetches the key from the mock
connector over HTTP — not only with `keyConnector`, where the test hands over a key it already had.

## Comments

Describe **what the file contains and how its tests are shaped**. Do not justify the file's
existence or argue about what used to be uncovered — that is changelog, not documentation, and it
goes stale.

## Prove a test can fail

Before trusting a new assertion, break the thing it covers and confirm it fails. Most of the rules
above exist because an assertion that looked thorough turned out to be vacuous — a spot-check that
matched anything, an override that excused the value it was meant to check, a route table that
echoed back whatever it was sent.
