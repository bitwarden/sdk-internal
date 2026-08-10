// Using a PIN the way a user does: unlock with the master password once, enrol a PIN, then reopen the
// vault with nothing but the PIN.
//
// The PIN never leaves the device — it protects a locally stored envelope holding the user key, and
// nothing about it is ever sent to the server. That is asserted the way a user would notice it rather
// than by reading request bodies: after logging out and back in, the PIN no longer opens anything,
// because the envelope it unwrapped was only ever in local state.
//
// Every PIN unlock is preceded by `local.clearEphemeral()`, which drops the state an app loses when it
// is closed rather than merely locked. That is what makes the two lock types distinguishable:
// `BeforeFirstUnlock` writes a persistent envelope that survives a restart, `AfterFirstUnlock` only an
// ephemeral one that does not. Without the clear, a PIN enrolled either way still opens the vault and
// the difference between them is invisible — enrolling with `BeforeFirstUnlock` populates *both*
// envelopes, so the persistent path is only actually exercised once the ephemeral one is gone.
//
// Every unlock goes through `validateAfterLockUnlock`, so "the PIN worked" means the entire vault
// decrypted to the plaintext the committed vector records — not merely that a call returned.

import { ApiServer } from "../model-server/api-server";
import { installServers, type InstalledServers } from "../model-server/install";
import { LocalState } from "../model-server/local-state";
import {
  syncToLocalState,
  unlockMethodFor,
  validateAfterLockUnlock,
  validateAfterLogoutLogin,
} from "../model-server/sync";
import { loadUserVectors, userVector } from "../test-vectors/load";
import { TEST_PIN } from "../utils";

/** Unlocking pays the account's real KDF cost, and these tests unlock several times over. */
const TIMEOUT = 120_000;

const WRONG_PIN = "9999";

const users = loadUserVectors();

/** The cheapest master-password account in the set to unlock. */
const vector = userVector(users, "v1-pbkdf2-min-iterations");

describe("unlocking with a PIN", () => {
  let api: ApiServer;
  let servers: InstalledServers;
  let local: LocalState;

  /** An account synced down from the server and unlocked by master password, as a user starts. */
  async function arrange() {
    api = new ApiServer();
    api.seedUser(vector);
    servers = installServers({ api });
    local = new LocalState();
    await syncToLocalState(api, vector.account.email, local);
    return local.unlock(unlockMethodFor(api, vector.account.email));
  }

  /** Enrols a PIN on an unlocked client, then closes the app: nothing in-memory carries over. */
  async function enrolPinAndClose(
    client: Awaited<ReturnType<typeof arrange>>,
    lockType: "BeforeFirstUnlock" | "AfterFirstUnlock" = "BeforeFirstUnlock",
  ) {
    await client.user_crypto_management().pin_settings().set_pin(TEST_PIN, lockType);
    await local.clearEphemeral();
  }

  afterEach(() => {
    expect(servers.unmatched.map((request) => request.route)).toEqual([]);
    // No seeded account's password, user key, private key or master key may ever appear in a request
    // body. Policed by the server on every request, so no individual test has to remember to look.
    expect(api.secretLeaks()).toEqual([]);
    servers.restore();
  });

  it(
    "enrols a PIN, then reopens the vault with the PIN alone",
    async () => {
      // Arrange
      const client = await arrange();

      // Act
      await enrolPinAndClose(client);

      // Assert: reopen with the PIN, reading the persisted envelope out of local state exactly as a
      // restarted app would.
      await validateAfterLockUnlock(local, { pinState: { pin: TEST_PIN } }, vector);
    },
    TIMEOUT,
  );

  it(
    "keeps a BeforeFirstUnlock PIN working after the app is closed",
    async () => {
      // Arrange
      const client = await arrange();

      // Act
      await enrolPinAndClose(client, "BeforeFirstUnlock");

      // Assert: the persistent envelope is the whole point of this lock type — the PIN still opens the
      // vault with nothing in memory.
      expect(await local.bridge.get_ephemeral_pin_envelope()).toBeNull();
      await validateAfterLockUnlock(local, { pinState: { pin: TEST_PIN } }, vector);
    },
    TIMEOUT,
  );

  it(
    "stops an AfterFirstUnlock PIN working once the app is closed",
    async () => {
      // Arrange
      const client = await arrange();
      await client.user_crypto_management().pin_settings().set_pin(TEST_PIN, "AfterFirstUnlock");

      // The PIN opens the vault while the app is still running.
      await validateAfterLockUnlock(local, { pinState: { pin: TEST_PIN } }, vector);

      // Act: close the app.
      await local.clearEphemeral();

      // Assert: this lock type deliberately does not survive it, and the master password still does.
      await expect(local.unlock({ pinState: { pin: TEST_PIN } })).rejects.toBeDefined();
      await validateAfterLockUnlock(local, unlockMethodFor(api, vector.account.email), vector);
    },
    TIMEOUT,
  );

  it(
    "leaves the master password working after a PIN is enrolled",
    async () => {
      // Arrange
      const client = await arrange();

      // Act
      await enrolPinAndClose(client);

      // Assert: a PIN is an additional way in, not a replacement, so both routes still open the vault
      // — from this client's own local state and from a client that has only what the server holds.
      await validateAfterLockUnlock(local, unlockMethodFor(api, vector.account.email), vector);
      await validateAfterLogoutLogin(api, vector.account.email, vector);
    },
    TIMEOUT,
  );

  it(
    "stops opening the vault once the PIN is removed",
    async () => {
      // Arrange
      const client = await arrange();
      const pinSettings = client.user_crypto_management().pin_settings();
      await pinSettings.set_pin(TEST_PIN, "BeforeFirstUnlock");

      // Act
      await pinSettings.unset_pin();
      await local.clearEphemeral();

      // Assert: the PIN is dead, and the account is still reachable the way it was before.
      await expect(local.unlock({ pinState: { pin: TEST_PIN } })).rejects.toBeDefined();
      await validateAfterLockUnlock(local, unlockMethodFor(api, vector.account.email), vector);
    },
    TIMEOUT,
  );

  it(
    "refuses a PIN that is not the one enrolled",
    async () => {
      // Arrange
      const client = await arrange();

      // Act
      await enrolPinAndClose(client);

      // Assert: the wrong PIN opens nothing, while the enrolled one still does — so the rejection is
      // about the PIN and not about a PIN unlock being broken outright.
      await expect(local.unlock({ pinState: { pin: WRONG_PIN } })).rejects.toBeDefined();
      await validateAfterLockUnlock(local, { pinState: { pin: TEST_PIN } }, vector);
    },
    TIMEOUT,
  );

  it(
    "does not carry the PIN across a logout, because the envelope is local only",
    async () => {
      // Arrange
      const client = await arrange();
      await enrolPinAndClose(client);

      // Act: log out and back in — local state is discarded and everything comes from the server.
      const returning = await validateAfterLogoutLogin(api, vector.account.email, vector);

      // Assert: the PIN cannot open the returning client, which is only true if the envelope was never
      // sent to the server in the first place.
      await expect(returning.unlock({ pinState: { pin: TEST_PIN } })).rejects.toBeDefined();
    },
    TIMEOUT,
  );
});
