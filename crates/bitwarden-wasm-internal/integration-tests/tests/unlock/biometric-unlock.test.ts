// Biometric unlock requested across the clients on one device.
//
// The desktop app owns the biometric prompt and the keychain; every other client asks it over IPC.
// The browser here is a real, logged-in, locked client, so a successful request has to leave it
// able to decrypt the vault it synced down — not merely holding some bytes.

import {
  BiometricsStatus,
  init_sdk,
  ipcRegisterBiometricsHandlers,
  ipcRequestAuthenticateBiometrics,
  ipcRequestGetBiometricsStatus,
  ipcRequestUnlockBiometrics,
  type BiometricsUnlock,
  type SymmetricKey,
} from "@bitwarden/sdk-internal";

import type { ClientEmulator } from "../../client-emulator/client-emulator";
import { BROWSER_BACKGROUND, DESKTOP_RENDERER, IpcBus } from "../../client-emulator/transport";
import { makeBiometricsDriver } from "../../client-emulator/unlock-drivers";
import { expectedVaultOf, validateLocalState } from "../../client-emulator/validate";
import { testHarness, type TestHarness } from "../../test-harness";
import { loadUserVectors, toSeedAccount, userVector } from "../../vectors/load";
import { asUserId } from "../type-assertion-helpers";

import { delay, isUnlocked, PEER_TIMEOUT } from "./peer-support";

/** The cheapest master-password account to unlock; the request is what a case pays for. */
const VECTOR = userVector(loadUserVectors(), "v1-pbkdf2-min-iterations");
const ACCOUNT = toSeedAccount(VECTOR);
const PASSWORD = VECTOR.account.password;

describe("biometric unlock over ipc", () => {
  let harness: TestHarness;
  let bus: IpcBus;
  let email: string;
  /** The unlocked desktop app, which answers biometrics requests. */
  let desktop: ClientEmulator;
  /** The locked browser extension, which makes them. */
  let browser: ClientEmulator;
  let userId: ReturnType<typeof asUserId>;

  /** Puts `driver` behind the desktop's biometrics handlers. Defaults to the desktop's own key. */
  async function respondWith(driver?: BiometricsUnlock): Promise<void> {
    await ipcRegisterBiometricsHandlers(desktop.ipc, driver ?? makeBiometricsDriver(desktop));
  }

  beforeEach(async () => {
    init_sdk();

    harness = testHarness();
    email = harness.server.seedUser(ACCOUNT).email;
    bus = new IpcBus();

    desktop = harness.newClientEmulator();
    desktop.setIpcSource(DESKTOP_RENDERER);
    await desktop.login(email);
    await desktop.unlock(PASSWORD);
    await desktop.attachIpc(bus);

    browser = harness.newClientEmulator();
    browser.setIpcSource(BROWSER_BACKGROUND);
    await browser.login(email);
    await browser.attachIpc(bus);

    userId = asUserId(browser.local.account.userId);
  }, PEER_TIMEOUT);

  afterEach(async () => {
    harness.restore();
    await delay(100);
  });

  it(
    "reports the desktop's biometrics status to the browser",
    async () => {
      await respondWith(makeBiometricsDriver(desktop, { status: BiometricsStatus.UnlockNeeded }));

      expect(await ipcRequestGetBiometricsStatus(browser.ipc, userId)).toBe(
        BiometricsStatus.UnlockNeeded,
      );
    },
    PEER_TIMEOUT,
  );

  it(
    "hands over a key that opens the browser's vault",
    async () => {
      await respondWith();

      // 1. Ask the desktop to unlock with biometrics
      const response = await ipcRequestUnlockBiometrics(browser.ipc, userId);
      if (response.user_key === undefined) {
        throw new Error("the desktop returned no user key");
      }

      // 2. The browser unlocks with what came back, as a real client would
      await browser.unlockWithUserKey(response.user_key);

      // 3. What came back decrypts the vault the browser synced down
      await validateLocalState(
        browser.local,
        { decryptedKey: { decrypted_user_key: response.user_key } },
        expectedVaultOf(ACCOUNT),
      );
    },
    PEER_TIMEOUT,
  );

  it(
    "leaves the browser locked when the prompt is canceled",
    async () => {
      await respondWith(makeBiometricsDriver(desktop, { unlockSucceeds: false }));

      const response = await ipcRequestUnlockBiometrics(browser.ipc, userId);

      expect(response.user_key).toBeUndefined();
      expect(await isUnlocked(browser)).toBe(false);
    },
    PEER_TIMEOUT,
  );

  it.each([true, false])(
    "forwards a user verification result of %s",
    async (uvResult) => {
      await respondWith(makeBiometricsDriver(desktop, { uvResult }));

      expect(await ipcRequestAuthenticateBiometrics(browser.ipc)).toBe(uvResult);
    },
    PEER_TIMEOUT,
  );

  it(
    "does not settle an in-flight unlock when a concurrent status response arrives",
    async () => {
      const userKey = await desktop.userKey();
      let releaseUnlock!: (key: SymmetricKey | undefined) => void;
      const unlockGate = new Promise<SymmetricKey | undefined>((resolve) => {
        releaseUnlock = resolve;
      });

      await respondWith({
        get_biometrics_status: async () => BiometricsStatus.Available,
        // Stays pending until the test releases it, so the unlock request below is guaranteed to
        // still be in flight.
        unlock_biometrics: () => unlockGate,
        authenticate_biometrics: async () => true,
      });

      // Capture the unlock's settled state without awaiting it, so that if the concurrent status
      // request below were to settle the unlock early, it surfaces as a failed assertion rather
      // than an unhandled rejection.
      const unlock = ipcRequestUnlockBiometrics(browser.ipc, userId).then(
        (ok) => ({ ok }),
        (err) => ({ err: String(err) }),
      );

      // A status request completes while the unlock is still in flight. Its response is delivered
      // only to that request's own response topic, so it must leave the pending unlock untouched.
      await expect(ipcRequestGetBiometricsStatus(browser.ipc, userId)).resolves.toBe(
        BiometricsStatus.Available,
      );

      releaseUnlock(userKey);

      expect(await unlock).toEqual({ ok: { user_key: userKey } });
    },
    PEER_TIMEOUT,
  );
});
