import { UserId } from "@bitwarden/sdk-internal";
import { flushAsyncQueue, setupSharedUnlockPair, testSymmetricKey } from "./utils";

const USER_A = "00000000-0000-0000-0000-000000000001" as unknown as UserId;

describe("shared unlock ipc", () => {
  it("unlocks the leader when the follower reports a manual unlock", async () => {
    const { follower, leaderHandle, cleanup } = await setupSharedUnlockPair();
    try {
      const key = testSymmetricKey(0x11);
      await follower.handle_device_event({
        ManualUnlock: { user_id: USER_A, user_key: key },
      });
      await flushAsyncQueue();
      expect(leaderHandle.getUserKey(USER_A)).toBe(key);
    } finally {
      await cleanup();
    }
  });

  it("locks the leader when the follower reports a manual lock", async () => {
    const key = testSymmetricKey(0x22);
    const { follower, leaderHandle, cleanup } = await setupSharedUnlockPair({
      leader: { initialStates: new Map([[USER_A, key]]) },
      follower: { initialStates: new Map([[USER_A, key]]) },
    });
    try {
      await follower.handle_device_event({ ManualLock: { user_id: USER_A } });
      await flushAsyncQueue();
      expect(leaderHandle.getUserKey(USER_A)).toBeUndefined();
    } finally {
      await cleanup();
    }
  });

  it("unlocks the follower when the leader reports a manual unlock", async () => {
    // Both peers know about USER_A in the locked state so the follower's
    // `start_sessions` registers itself with the leader. Otherwise the leader
    // has no active follower endpoints to broadcast to.
    const { leader, followerHandle, cleanup } = await setupSharedUnlockPair({
      leader: { initialStates: new Map([[USER_A, undefined]]) },
      follower: { initialStates: new Map([[USER_A, undefined]]) },
    });
    try {
      const key = testSymmetricKey(0x44);
      await leader.handle_device_event({
        ManualUnlock: { user_id: USER_A, user_key: key },
      });
      await flushAsyncQueue();
      expect(followerHandle.getUserKey(USER_A)).toBe(key);
    } finally {
      await cleanup();
    }
  });

  it("locks the follower when the leader reports a manual lock", async () => {
    const key = testSymmetricKey(0x33);
    const { leader, followerHandle, cleanup } = await setupSharedUnlockPair({
      leader: { initialStates: new Map([[USER_A, key]]) },
      follower: { initialStates: new Map([[USER_A, key]]) },
    });
    try {
      await leader.handle_device_event({ ManualLock: { user_id: USER_A } });
      await flushAsyncQueue();
      expect(followerHandle.getUserKey(USER_A)).toBeUndefined();
    } finally {
      await cleanup();
    }
  });
});
