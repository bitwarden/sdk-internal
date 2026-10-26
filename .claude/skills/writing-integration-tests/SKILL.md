---
name: writing-integration-tests
description:
  Write integration tests for the SDK — WASM tests in
  `crates/bitwarden-wasm-internal/integration-tests`, or Rust integration tests with their own
  harness (e.g. `bitwarden-shared-unlock/tests`). Use when asked to "add an integration test", "test
  X across the FFI boundary", "test X end to end", reproduce a bug against the built wasm package,
  or extend the server/client emulator.
---

# Writing integration tests

**The core principle: a test harness lets you write the test at a high level.** A test reads like a
user story — seed, log in, unlock, act, verify — in domain terms. Mechanics (HTTP, state wiring, key
plumbing, transports) live in the harness. If a test needs low-level setup, extend the harness
instead.

## Pick where it lives

- **WASM integration tests** (`crates/bitwarden-wasm-internal/integration-tests`, TS/vitest): drive
  the **built** `@bitwarden/sdk-internal` package like a real client. Use for flows across client ↔
  server, and anything where FFI/serde conversions or the wasm executor matter.
- **Rust integration tests with a harness** (`crates/<crate>/tests/`): use when the behavior is a
  protocol or multi-party flow inside one crate and the FFI adds nothing. Reference:
  `bitwarden-shared-unlock/tests/` — `harness/` (simulated devices, in-memory IPC transport,
  topologies, log-based assertions) and `scenarios/` (one file per topology/concern, tests read as
  `follower.manual_unlock(...)` → `wait_for_devices_reaching_state(...)`). Build a harness like that
  before writing scenarios.
- Single-function logic stays in Rust unit tests.

## WASM harness

```
 test ──► ClientEmulator ──► PasswordManagerClient (wasm) ──fetch──► HttpMock ──► ServerEmulator
             │  LocalState: WasmStateBridge + TestRepository<Cipher|Folder|Policy>      │
             └──────────────── sync / unlock / lock / restart ◄──── Database (seeded from test-vectors/)
```

| Path                              | Role                                                                                       |
| --------------------------------- | ------------------------------------------------------------------------------------------ |
| `test-harness.ts`                 | `testHarness()` → `{ server, newClientEmulator(), restore() }`; installs the fetch hook    |
| `server-emulator/server-emulator` | `seedUserTestVector`, `seedOrganization`, `seedEmergencyAccessTestVector`, `getUser`, `db` |
| `server-emulator/api-server.ts`   | Route model (`/sync`, kdf, rotation, ciphers, folders…) with real server rules (409, 400)  |
| `server-emulator/dto.ts`          | Server wire DTOs + converters (`SyncResponse.forUser`, `CipherRequest.toCipher`…)          |
| `server-emulator/http-mock.ts`    | Fetch hook; records `requests`, `unmatched`, `bodyFor`, `called`                           |
| `client-emulator/`                | `ClientEmulator` (`login`, `sync`, `unlock`, `unlockWith`, `lock`, `restart`, `reinit`)    |
| `client-emulator/validate.ts`     | `validateVault(client, seed, ignore)`, `validateCiphers`, `expectPlaintextEqual`           |
| `vectors/test-vectors.ts`         | `testVectors.users` / `.emergencyAccess` selectors; `.each`, `.eachUnlockMethod`           |
| `/test-vectors/**.json` (repo)    | Committed accounts: keys, unlock methods, encrypted + decrypted vault                      |
| `tests/utils.ts`                  | `makeStateBridge`, `rejection`, IPC transport/biometrics mocks                             |
| `tests/type-assertion-helpers.ts` | `asUserId`, `asEncString`, `asKeyId`… — branded-type casts                                 |
| `perf/*.perf.ts`                  | Benchmarks (`npm run perf`), not tests                                                     |

Pick vectors by reading each JSON's `description` and `unlockMethods`.

### Template

```ts
import { validateVault } from "../../client-emulator/validate";
import { testHarness, type TestHarness } from "../../test-harness";
import { testVectors } from "../../vectors/test-vectors";

const TIMEOUT = 120_000; // KDF + wasm is slow

describe("feature", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  testVectors.users.withMasterPassword().each(
    "$name keeps its vault after X",
    async (vector) => {
      const seeded = harness.server.seedUserTestVector(vector);
      const client = harness.newClientEmulator();
      await client.login(seeded.email);
      await client.unlock(vector.account.password);

      // 1. Act through the SDK
      await client.getPasswordManagerClient().user_crypto_management().change_kdf(/* … */);

      // 2. Verify local state: lock, unlock, decrypt
      await client.lock();
      await client.unlock(vector.account.password);
      await validateVault(client, seeded.seed);

      // 3. Verify server state: a fresh client logs in and decrypts
      const relogin = harness.newClientEmulator();
      await relogin.login(seeded.email);
      await relogin.unlock(vector.account.password);
      await validateVault(relogin, seeded.seed);
    },
    TIMEOUT,
  );
});
```

### Rules

- **Raw route mocks are discouraged.** Don't call `installHttpMock({ [ROUTE]: … })` from a test, and
  don't hand-build initialized clients from fixtures (`make*Client`). Existing tests that do
  (`organization-domains`, `invite-link`, `crypto-sync-handler`, `collections-client`) are legacy;
  don't copy them. Missing route → model it in `ApiServer` (or the right service) like the real
  server, refusals included. Missing state → add a seeding helper to the emulator.
- **Never mutate crypto state directly via the state bridge.** Crypto state reaches the client only
  via `sync()` → crypto sync handler → state bridge. The password is the only secret a test
  supplies.
- **Verify both sides.** Local: `lock()`/`unlock()` then `validateVault`. Server: new
  `ClientEmulator` → `login` → `unlock` → `validateVault`. Assert server rows via
  `harness.server.getUser(email)` / `server.db`; local state via `client.bridge.get_*()`.
- **Multi-device** flows: two emulators on one harness; call `second.sync(email)` explicitly (no
  push notifications). Draw an ASCII timeline in the test's doc comment (see `change-kdf.test.ts`,
  `rotate-user-keys.test.ts`).
- **Failures**: `rejection(promise, isXxxError)`, assert `error.variant`, then assert neither side
  changed.
- **Ignore lists**: `validateVault` ignores `revisionDate`/`creationDate`. Pass `[]` when nothing
  was written; extend (`[...IGNORED_FIELDS, "key"]`) only for fields the operation legitimately
  changes.
- **Run over all vectors** with `.each` / `.eachUnlockMethod`; narrow with `.withMasterPassword()`
  and `.except(name)`. Document why a vector is excluded.
- **Vectors are permanent.** Never edit or regenerate a committed vector to make a test pass — that
  is a backward-compat break. `unlock/test-vector-stability.test.ts` pins the set; adding a vector
  means updating that list.
- Unmatched routes return 501 (not a throw) and land in `harness`'s mock `unmatched` — check it when
  a call fails oddly.
- Tests use vitest globals; number steps `// 1. …`, `// 2. Verify …`.

### Run

```bash
cd crates/bitwarden-wasm-internal/integration-tests && npm ci && npm run build:test
```

`build:test` builds wasm (`../build.sh`) into `../npm/`, then typechecks and runs vitest. After the
first build, if only TS changed: `npm test`, or `npx vitest run tests/<path>.test.ts`. Rebuild after
any Rust change. CI runs `npm test` on a fresh build.

Rust harness tests: `cargo test -p <crate> --test <name>`; add `RUST_LOG=debug … -- --nocapture` for
one test's logs.
