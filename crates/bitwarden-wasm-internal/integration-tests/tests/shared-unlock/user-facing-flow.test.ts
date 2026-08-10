// Unlock state shared between two clients on one device, over IPC.
//
// Two subjects, both driven end to end through a real transport pair rather than by calling the handlers
// directly. Biometrics: a requester asks the responder for its status, for an unlock, and for a user
// verification check, and gets back whatever the responder's driver decided. Shared unlock: a leader and
// a follower mirror each other's lock and unlock events, and keep doing so after either side is
// process-reloaded.

import {
  BiometricsStatus,
  IpcClient,
  ipcRegisterBiometricsHandlers,
  ipcRequestAuthenticateBiometrics,
  ipcRequestGetBiometricsStatus,
  ipcRequestUnlockBiometrics,
  init_sdk,
} from "@bitwarden/sdk-internal";

import { asUserId } from "../type-assertion-helpers";
import {
  makeMockBiometricsDriver,
  makeMockTransportPair,
  reloadFollower,
  reloadLeader,
  setupSharedUnlockPair,
  sleep,
  TEST_USER_ID,
  testSymmetricKey,
} from "../utils";

async function setupClientPair(driver = makeMockBiometricsDriver()) {
  init_sdk();

  const [requesterBackend, responderBackend] = makeMockTransportPair();
  const requester = IpcClient.newWithSdkInMemorySessions(requesterBackend);
  const responder = IpcClient.newWithSdkInMemorySessions(responderBackend);

  await requester.start();
  await responder.start();

  await ipcRegisterBiometricsHandlers(responder, driver);

  return { requester, responder };
}

describe("biometrics ipc", () => {
  it("returns the responder's biometrics status", async () => {
    const { requester } = await setupClientPair(
      makeMockBiometricsDriver({
        userKey: testSymmetricKey(),
        uvResult: true,
        status: BiometricsStatus.UnlockNeeded,
      }),
    );

    const status = await ipcRequestGetBiometricsStatus(requester, TEST_USER_ID);

    expect(status).toBe(BiometricsStatus.UnlockNeeded);
  });

  it("returns the user key on successful biometric unlock", async () => {
    const userKey = testSymmetricKey(0x37);
    const { requester } = await setupClientPair(
      makeMockBiometricsDriver({ userKey, uvResult: true, status: BiometricsStatus.Available }),
    );

    const response = await ipcRequestUnlockBiometrics(requester, TEST_USER_ID);

    expect(response.user_key).toBe(userKey);
  });

  it("returns undefined when biometric unlock is canceled or fails", async () => {
    const { requester } = await setupClientPair(
      makeMockBiometricsDriver({
        userKey: undefined,
        uvResult: false,
        status: BiometricsStatus.UnlockNeeded,
      }),
    );

    const response = await ipcRequestUnlockBiometrics(requester, TEST_USER_ID);

    expect(response.user_key).toBeUndefined();
  });

  it("forwards a successful biometrics UV check", async () => {
    const { requester } = await setupClientPair(
      makeMockBiometricsDriver({
        userKey: undefined,
        uvResult: true,
        status: BiometricsStatus.Available,
      }),
    );

    expect(await ipcRequestAuthenticateBiometrics(requester)).toBe(true);
  });

  it("forwards a failed biometrics UV check", async () => {
    const { requester } = await setupClientPair(
      makeMockBiometricsDriver({
        userKey: undefined,
        uvResult: false,
        status: BiometricsStatus.Available,
      }),
    );

    expect(await ipcRequestAuthenticateBiometrics(requester)).toBe(false);
  });
});

const USER_A = asUserId("00000000-0000-0000-0000-000000000001");
const USER_KEY = testSymmetricKey(0x11);
const USER_A_LOCKED_STATE = new Map([[USER_A, undefined]]);
const USER_A_UNLOCKED_STATE = new Map([[USER_A, USER_KEY]]);
const UNLOCK_EVENT = { ManualUnlock: { user_id: USER_A, user_key: USER_KEY } };
const LOCK_EVENT = { ManualLock: { user_id: USER_A } };

describe("shared unlock ipc", () => {
  it("unlocks the leader when the follower reports a manual unlock", async () => {
    const { follower, leaderDriver: leaderHandle } = await setupSharedUnlockPair({
      leader: { initialStates: USER_A_LOCKED_STATE },
      follower: { initialStates: USER_A_LOCKED_STATE },
    });

    await follower.handle_device_event(UNLOCK_EVENT);
    await sleep(20);
    expect(leaderHandle.getUserKey(USER_A)).toBe(USER_KEY);
  });

  it("locks the leader when the follower reports a manual lock", async () => {
    const { follower, leaderDriver: leaderHandle } = await setupSharedUnlockPair({
      leader: { initialStates: USER_A_UNLOCKED_STATE },
      follower: { initialStates: USER_A_UNLOCKED_STATE },
    });

    await follower.handle_device_event(LOCK_EVENT);
    await sleep(20);
    expect(leaderHandle.getUserKey(USER_A)).toBeUndefined();
  });

  it("unlocks the follower when the leader reports a manual unlock", async () => {
    const { leader, followerDriver: followerHandle } = await setupSharedUnlockPair({
      leader: { initialStates: USER_A_LOCKED_STATE },
      follower: { initialStates: USER_A_LOCKED_STATE },
    });

    await leader.handle_device_event(UNLOCK_EVENT);
    await sleep(20);
    expect(followerHandle.getUserKey(USER_A)).toBe(USER_KEY);
  });

  it("locks the follower when the leader reports a manual lock", async () => {
    const { leader, followerDriver: followerHandle } = await setupSharedUnlockPair({
      leader: { initialStates: USER_A_UNLOCKED_STATE },
      follower: { initialStates: USER_A_UNLOCKED_STATE },
    });

    await leader.handle_device_event(LOCK_EVENT);
    await sleep(20);
    expect(followerHandle.getUserKey(USER_A)).toBeUndefined();
  });

  it("reconnects after process-reloading a follower", async () => {
    const pair = await setupSharedUnlockPair({
      leader: { initialStates: USER_A_UNLOCKED_STATE },
      follower: { initialStates: USER_A_UNLOCKED_STATE },
    });
    await sleep(20);
    expect(pair.leaderDriver.getUserKey(USER_A)).toBe(USER_KEY);
    expect(pair.followerDriver.getUserKey(USER_A)).toBe(USER_KEY);

    const reloaded = await reloadFollower(pair, {
      follower: { initialStates: USER_A_LOCKED_STATE },
    });
    await sleep(20);

    expect(reloaded.followerDriver.getUserKey(USER_A)).toBe(USER_KEY);
    expect(reloaded.leaderDriver.getUserKey(USER_A)).toBe(USER_KEY);
  });

  it("reconnects after process-reloading the leader", async () => {
    const pair = await setupSharedUnlockPair({
      leader: { initialStates: USER_A_UNLOCKED_STATE },
      follower: { initialStates: USER_A_UNLOCKED_STATE },
    });
    await sleep(20);
    expect(pair.leaderDriver.getUserKey(USER_A)).toBe(USER_KEY);
    expect(pair.followerDriver.getUserKey(USER_A)).toBe(USER_KEY);

    const reloaded = await reloadLeader(pair, {
      leader: { initialStates: USER_A_LOCKED_STATE },
    });
    // Wait for heartbeat
    // Note: Currently, there is two heartbeats necessary; Basically:
    // - Leader reloads, has no crypto state, follower still has crypto session A
    // - Follower sends heartbeat 1 with session A, leader doesn't recognize session A, sends crypto state invalidated back
    // - Follower performs handshake, now both follower and leader have crypto session B
    // - Follower sends heartbeat 2 with session B, leader sets up unlock sharing session
    // - As of here, a unlock event will work.
    //
    // This could be fixed differently on the crypto layer in the future
    await sleep(5000);

    expect(reloaded.leaderDriver.getUserKey(USER_A)).toBe(USER_KEY);
    expect(reloaded.followerDriver.getUserKey(USER_A)).toBe(USER_KEY);
  }, 15000);
});
