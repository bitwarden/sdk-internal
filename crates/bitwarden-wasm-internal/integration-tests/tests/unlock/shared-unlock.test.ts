// Shared unlock across the clients on one device.
//
// The protocol's own rules are covered in Rust, in `bitwarden-shared-unlock`. What is proven here
// is the end of the chain the SDK cannot see: that the key a peer receives over IPC, hands to the
// device driver, and unlocks with, actually opens that client's vault.

import { SharedUnlockPeer, init_sdk, type SharedUnlockClient } from "@bitwarden/sdk-internal";

import { expectedVaultOf, validateLocalState } from "../../client-emulator/validate";
import { BROWSER_BACKGROUND, DESKTOP_RENDERER, IpcBus, WEB } from "../../client-emulator/transport";
import { testHarness, type TestHarness } from "../../test-harness";
import { loadUserVectors, toSeedAccount, userVector } from "../../vectors/load";

import {
  delay,
  isUnlocked,
  joinDevice,
  PEER_TIMEOUT,
  SYNC_INTERVAL_MS,
  userKeyOf,
  waitFor,
  type Device,
} from "./peer-support";

/** The cheapest master-password account to unlock; the propagation is what a case pays for. */
const VECTOR = userVector(loadUserVectors(), "v1-pbkdf2-min-iterations");
const ACCOUNT = toSeedAccount(VECTOR);
const PASSWORD = VECTOR.account.password;

describe("shared unlock", () => {
  let harness: TestHarness;
  let bus: IpcBus;
  let email: string;
  let desktop: Device;
  let browser: Device;

  const peers: SharedUnlockPeer[] = [];
  const running: AbortController[] = [];

  /**
   * Brings a peer up for one user.
   *
   * A peer sends nothing for a user until it is told which clients that user may be shared with,
   * so the destinations are part of starting it rather than an afterthought.
   */
  async function startPeer(device: Device, destinations: SharedUnlockClient[]) {
    const peer = new SharedUnlockPeer(device.client.ipc, device.driver);
    peer.set_destinations(device.userId, destinations);

    const abort = new AbortController();
    running.push(abort);
    peers.push(peer);

    await peer.start(abort);

    return peer;
  }

  beforeEach(async () => {
    init_sdk();

    harness = testHarness();
    email = harness.server.seedUser(ACCOUNT).email;
    bus = new IpcBus();

    desktop = await joinDevice(harness, bus, email, DESKTOP_RENDERER, "desktop");
    browser = await joinDevice(harness, bus, email, BROWSER_BACKGROUND, "browser");
  }, PEER_TIMEOUT);

  afterEach(async () => {
    for (const abort of running) {
      abort.abort();
    }
    running.length = 0;
    peers.length = 0;

    harness.restore();

    // Lets the aborted sync loops settle before the next test replaces the fetch hook.
    await delay(100);
  });

  it(
    "unlocks the browser with a key that opens its vault when the desktop unlocks",
    async () => {
      // 1. The desktop unlocks; the browser is logged in but locked
      await desktop.client.unlock(PASSWORD);
      expect(await isUnlocked(browser.client)).toBe(false);

      const desktopPeer = await startPeer(desktop, ["Browser"]);
      await startPeer(browser, ["Desktop"]);

      // 2. Report the unlock to the shared-unlock system
      await desktopPeer.handle_device_event({
        ManualUnlock: { user_id: desktop.userId, user_key: await desktop.client.userKey() },
      });

      // 3. The browser is unlocked by its driver, not by the test
      await waitFor(() => isUnlocked(browser.client), "the browser to be unlocked");

      // 4. The key the browser was left holding decrypts the vault it synced down. Reading it back
      //    out of the browser's own state is the point: a validation against the vector's key would
      //    pass even if the propagated key were wrong.
      const propagated = await userKeyOf(browser.client);
      if (propagated === undefined) {
        throw new Error("the browser reports unlocked but holds no user key");
      }

      await validateLocalState(
        browser.client.local,
        { decryptedKey: { decrypted_user_key: propagated } },
        expectedVaultOf(ACCOUNT),
      );
    },
    PEER_TIMEOUT,
  );

  it(
    "unlocks the desktop with a key that opens its vault when the browser unlocks",
    async () => {
      // 1. This time the follower is the one that unlocks, and the leader is the one that follows
      await browser.client.unlock(PASSWORD);
      expect(await isUnlocked(desktop.client)).toBe(false);

      await startPeer(desktop, ["Browser"]);
      const browserPeer = await startPeer(browser, ["Desktop"]);

      // 2. Report the unlock to the shared-unlock system
      await browserPeer.handle_device_event({
        ManualUnlock: { user_id: browser.userId, user_key: await browser.client.userKey() },
      });

      // 3. The desktop is unlocked, and what it holds decrypts its vault
      await waitFor(() => isUnlocked(desktop.client), "the desktop to be unlocked");

      const propagated = await userKeyOf(desktop.client);
      if (propagated === undefined) {
        throw new Error("the desktop reports unlocked but holds no user key");
      }

      await validateLocalState(
        desktop.client.local,
        { decryptedKey: { decrypted_user_key: propagated } },
        expectedVaultOf(ACCOUNT),
      );
    },
    PEER_TIMEOUT,
  );

  it(
    "locks the browser when the desktop locks",
    async () => {
      // 1. Get both clients unlocked through the protocol
      await desktop.client.unlock(PASSWORD);

      const desktopPeer = await startPeer(desktop, ["Browser"]);
      await startPeer(browser, ["Desktop"]);

      await desktopPeer.handle_device_event({
        ManualUnlock: { user_id: desktop.userId, user_key: await desktop.client.userKey() },
      });
      await waitFor(() => isUnlocked(browser.client), "the browser to be unlocked");

      // 2. Lock the desktop
      await desktopPeer.handle_device_event({ ManualLock: { user_id: desktop.userId } });

      // 3. The browser drops the key it was given
      await waitFor(async () => !(await isUnlocked(browser.client)), "the browser to be locked");
    },
    PEER_TIMEOUT,
  );

  it(
    "withholds the unlock from a web client the user is not shared with",
    async () => {
      // 1. A third client joins the bus below the browser, and is origin-valid for this account
      const web = await joinDevice(harness, bus, email, WEB, "web");

      await desktop.client.unlock(PASSWORD);

      const desktopPeer = await startPeer(desktop, ["Browser"]);
      // The browser relays upward only: the web client may sync to it, but is not a destination.
      await startPeer(browser, ["Desktop"]);
      await startPeer(web, ["Browser"]);

      // 2. Unlock, and let it propagate as far as it is going to
      await desktopPeer.handle_device_event({
        ManualUnlock: { user_id: desktop.userId, user_key: await desktop.client.userKey() },
      });
      await waitFor(() => isUnlocked(browser.client), "the browser to be unlocked");

      // 3. A full interval later — enough for a periodic sync, not just the event — the web client
      //    is still locked, because it is not in anyone's destinations for this user.
      await delay(SYNC_INTERVAL_MS + 1000);

      expect(await isUnlocked(web.client)).toBe(false);
    },
    PEER_TIMEOUT,
  );

  it(
    "suppresses the follower's vault timeout while the session is shared",
    async () => {
      await desktop.client.unlock(PASSWORD);

      await startPeer(desktop, ["Browser"]);
      await startPeer(browser, ["Desktop"]);

      // Only syncs arriving from a peer's leader suppress a timeout, so this is the browser's
      // evidence that the desktop is still there.
      await delay(SYNC_INTERVAL_MS + 1000);

      expect(browser.suppressions.length).toBeGreaterThan(0);
      for (const suppression of browser.suppressions) {
        expect(suppression).toBeGreaterThan(0);
      }
    },
    PEER_TIMEOUT,
  );
});
