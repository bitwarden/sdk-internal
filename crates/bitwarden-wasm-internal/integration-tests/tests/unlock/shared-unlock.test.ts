/**
 * Boundary tests for the shared-unlock WASM surface.
 *
 * The protocol itself is covered in Rust, in `bitwarden-shared-unlock/tests`.
 * This test suite just tests basic wasm functionality / crossing the FFI boundary.
 */
import {
  IpcClient,
  SharedUnlockDriver,
  SharedUnlockPeer,
  SymmetricKey,
  UserId,
  init_sdk,
} from "@bitwarden/sdk-internal";

import { makeMockTransportPair, testSymmetricKey } from "../utils";

const USER_A = "00000000-0000-0000-0000-000000000001" as unknown as UserId;
const USER_KEY = testSymmetricKey(0x11);

/** Matches `SYNC_INTERVAL` in `bitwarden-shared-unlock/src/lib.rs`. */
const SYNC_INTERVAL_MS = 5000;

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

interface MockDriver {
  driver: SharedUnlockDriver;
  /** `undefined` means locked. */
  getUserKey(): SymmetricKey | undefined;
  suppressions: number[];
}

/**
 * Minimal `SharedUnlockDriver` implementation. Every method here exists to be called across the
 * binding, so an adapter that stops marshalling one of them shows up as a failure below.
 */
function makeDriver(
  clientName: "browser" | "desktop",
  initialKey: SymmetricKey | undefined,
): MockDriver {
  let key = initialKey;
  const suppressions: number[] = [];

  return {
    driver: {
      lock_user: async () => {
        key = undefined;
      },
      unlock_user: async (_user_id, user_key) => {
        key = user_key;
      },
      list_users: async () => [USER_A],
      suppress_vault_timeout: async (_user_id, suppression_duration) => {
        suppressions.push(suppression_duration);
      },
      get_client_name: async () => clientName,
      get_vault_url: async () => undefined,
    },
    getUserKey: () => key,
    suppressions,
  };
}

/**
 * A browser peer that syncs up to a desktop peer. `get_client_name` is what feeds
 * `discover_leader`, so the desktop reporting `"desktop"` is what makes it the top of the hierarchy.
 */
async function setupPair(options: {
  leaderKey: SymmetricKey | undefined;
  followerKey: SymmetricKey | undefined;
}) {
  init_sdk();

  const [followerBackend, leaderBackend] = makeMockTransportPair(
    { BrowserBackground: { id: "Own" } },
    "DesktopRenderer",
  );

  const leaderIpc = IpcClient.newWithSdkInMemorySessions(leaderBackend);
  const followerIpc = IpcClient.newWithSdkInMemorySessions(followerBackend);
  await leaderIpc.start();
  await followerIpc.start();

  const leaderDriver = makeDriver("desktop", options.leaderKey);
  const followerDriver = makeDriver("browser", options.followerKey);

  const leader = new SharedUnlockPeer(leaderIpc, leaderDriver.driver);
  const follower = new SharedUnlockPeer(followerIpc, followerDriver.driver);

  // A peer sends to nothing until told which clients it may share with: the desktop leader serves
  // the browser below it, the browser follower syncs up to the desktop.
  leader.set_destinations(["Browser"]);
  follower.set_destinations(["Desktop"]);

  const leaderAbort = new AbortController();
  const followerAbort = new AbortController();
  await leader.start(leaderAbort);
  await follower.start(followerAbort);

  return {
    leader,
    follower,
    leaderDriver,
    followerDriver,
    cleanup: () => {
      leaderAbort.abort();
      followerAbort.abort();
    },
  };
}

/** Polls, because how quickly a sync lands depends on where in the tick it is reported. */
async function waitForKey(
  read: () => SymmetricKey | undefined,
  expected: SymmetricKey | undefined,
  timeoutMs = 20000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  const describe = (key: SymmetricKey | undefined) => (key === undefined ? "locked" : "unlocked");

  for (;;) {
    if (read() === expected) {
      return;
    }
    if (Date.now() >= deadline) {
      throw new Error(
        `Timed out after ${timeoutMs}ms waiting for ${describe(expected)}; it is ${describe(read())}`,
      );
    }
    await delay(25);
  }
}

describe("shared unlock wasm bindings", () => {
  let cleanup: (() => void) | undefined;

  afterEach(async () => {
    cleanup?.();
    cleanup = undefined;
    await delay(100);
  });

  it("constructs and starts a peer over the generated bindings", async () => {
    const pair = await setupPair({ leaderKey: undefined, followerKey: undefined });
    cleanup = pair.cleanup;

    expect(pair.leader).toBeInstanceOf(SharedUnlockPeer);
    expect(pair.follower).toBeInstanceOf(SharedUnlockPeer);
  }, 30000);

  it("shares unlock from follower to leader", async () => {
    const pair = await setupPair({ leaderKey: undefined, followerKey: undefined });
    cleanup = pair.cleanup;

    await pair.follower.handle_device_event({
      ManualUnlock: { user_id: USER_A, user_key: USER_KEY },
    });

    await waitForKey(() => pair.leaderDriver.getUserKey(), USER_KEY);
  }, 30000);

  it("calls suppress_vault_timeout with a duration in milliseconds", async () => {
    const pair = await setupPair({ leaderKey: undefined, followerKey: undefined });
    cleanup = pair.cleanup;

    await delay(SYNC_INTERVAL_MS + 1000);

    expect(pair.followerDriver.suppressions.length).toBeGreaterThan(0);
    for (const suppression of pair.followerDriver.suppressions) {
      expect(typeof suppression).toBe("number");
      expect(suppression).toBeGreaterThan(0);
    }
  }, 30000);
});
