// Key rotation against a real server.
//
// Opt-in through `BW_LIVE_SERVER_URL`; skipped otherwise. See `live/config.ts` and the Readme.

import { LoginMethod, type ClientEmulator } from "../../client-emulator/client-emulator";
import { IGNORED_FIELDS, validateVault } from "../../client-emulator/validate";
import { describeLoginFailure, liveConfig, requireLiveConfig } from "../../live/config";
import type { SeedVault } from "../../server-emulator/server-emulator";
import { liveHarness, type TestHarness } from "../../test-harness";
import { rotateByPassword } from "./rotate-helpers";

/** A real KDF derivation and a real round trip per step, over a vault of unknown size. */
const TIMEOUT = 300_000;

/** Enough consecutive rotations that a second one cannot pass by reusing the first one's state. */
const ROTATION_COUNT = 3;

const ROTATED_FIELDS = [...IGNORED_FIELDS, "key"];

/** The item {@link ensureVaultNotEmpty} adds, named so it is obvious where it came from. */
const PLACEHOLDER_NAME = "sdk-internal integration tests";

const config = liveConfig();

/** Absent configuration skips the suite rather than failing it: a default run must not need it. */
const describeLive = config === undefined ? describe.skip : describe;

describeLive("rotate user keys (live server)", () => {
  let harness: TestHarness;

  beforeEach(() => {
    const live = requireLiveConfig();
    harness = liveHarness(live.settings, live.loginRequest);
  });

  afterEach(() => harness.restore());

  /** A client logged in, synced and unlocked, as a real one arrives at the vault. */
  async function loggedIn(): Promise<ClientEmulator> {
    const live = requireLiveConfig();

    const client = harness.newClientEmulator();
    try {
      await client.login(live.email, LoginMethod.Password, live.password);
    } catch (error) {
      throw new Error(describeLoginFailure(error));
    }

    await client.unlock(live.password);

    return client;
  }

  /**
   * Gives the account something to rotate, if it has nothing.
   *
   * A vault assertion over an empty vault compares nothing and passes however badly the rotation
   * went. Creating the item through the SDK also puts `POST /ciphers` in front of the real server,
   * which is the point of running live at all.
   */
  async function ensureVaultNotEmpty(client: ClientEmulator): Promise<void> {
    const sdk = client.getPasswordManagerClient();
    if ((await sdk.vault().ciphers().get_all()).successes.length > 0) {
      return;
    }

    await sdk
      .vault()
      .ciphers()
      .create({
        organizationId: undefined,
        collectionIds: [],
        folderId: undefined,
        name: PLACEHOLDER_NAME,
        notes: "Created by the live rotation tests. Safe to delete.",
        favorite: false,
        reprompt: 0,
        type: {
          login: {
            username: "integration-tests@example.com",
            password: "a password the rotation has to carry across",
            passwordRevisionDate: undefined,
            uris: undefined,
            totp: undefined,
            autofillOnPageLoad: undefined,
            fido2Credentials: undefined,
          },
        },
        fields: [],
      });

    await client.sync();
  }

  /**
   * What the account decrypts to right now, in the shape a vector records.
   */
  async function recordVault(client: ClientEmulator): Promise<{ vault: SeedVault }> {
    const sdk = client.getPasswordManagerClient();

    const { successes, failures } = await sdk.vault().ciphers().get_all();
    if (failures.length > 0) {
      const ids = failures.map((cipher) => String(cipher.id)).join(", ");
      throw new Error(`${failures.length} cipher(s) failed to decrypt: ${ids}`);
    }

    const folders = await sdk.vault().folders().list();
    if (successes.length === 0 && folders.length === 0) {
      throw new Error("the live account's vault is empty, so a rotation cannot be checked");
    }

    return {
      vault: {
        ciphers: client.local.ciphers.dump().map((encrypted) => ({
          id: String(encrypted.id),
          encrypted,
          decrypted: successes.find((cipher) => cipher.id === encrypted.id),
        })),
        folders: client.local.folders.dump().map((encrypted) => ({
          id: String(encrypted.id),
          encrypted,
          decrypted: folders.find((folder) => folder.id === encrypted.id),
        })),
      },
    };
  }

  /**
   * The account survives being rotated repeatedly, and a fresh login reads the result.
   *
   *   K0 ──rotate──▶ K1 ──rotate──▶ K2 ──rotate──▶ K3 ──▶ vault still decrypts, fresh login reads it
   *
   * Re-runnable: the first round upgrades a V1 account, and every round after is V2 to V2.
   */
  it(
    `survives ${ROTATION_COUNT} consecutive rotations`,
    async () => {
      const live = requireLiveConfig();
      const client = await loggedIn();

      await ensureVaultNotEmpty(client);
      const recorded = await recordVault(client);

      // 1. Rotate repeatedly, restarting the session onto each new key before the next round. The
      //    user key is read back every round, so a rotation that left the key untouched is caught
      //    here rather than by the vault assertion, which a no-op rotation would also pass.
      const userKeys = [await client.getPasswordManagerClient().crypto().get_user_encryption_key()];

      for (let round = 0; round < ROTATION_COUNT; round++) {
        await rotateByPassword(client.getPasswordManagerClient(), live.password, "CreateIfNeeded");

        await client.sync();
        await client.lock();
        await client.unlock(live.password);

        userKeys.push(await client.getPasswordManagerClient().crypto().get_user_encryption_key());
      }

      // 2. Verify every round produced a key of its own
      expect(new Set(userKeys).size).toBe(userKeys.length);

      // 3. Verify the account ended up V2, whichever generation it started at
      expect(await client.bridge.get_account_cryptographic_state()).toHaveProperty("V2");

      // 4. Verify the vault still decrypts to what it held before, over the last key
      await validateVault(client, recorded, ROTATED_FIELDS);

      // 5. Verify a client that logs in fresh reads it too, so the rotations left the server
      //    holding a consistent account and not just this session
      await validateVault(await loggedIn(), recorded, ROTATED_FIELDS);
    },
    TIMEOUT,
  );
});
