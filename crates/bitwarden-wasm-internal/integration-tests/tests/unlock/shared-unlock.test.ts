import { UserId } from "@bitwarden/sdk-internal";
import {
  sleep,
  setupSharedUnlockPair,
  reloadFollower,
  reloadLeader,
  testSymmetricKey,
} from "../utils";

const USER_A = "00000000-0000-0000-0000-000000000001" as unknown as UserId;
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

  it("delivers the follower's first message after a leader reload", async () => {
    const pair = await setupSharedUnlockPair({
      leader: { initialStates: USER_A_UNLOCKED_STATE },
      follower: { initialStates: USER_A_UNLOCKED_STATE },
    });
    await sleep(20);
    expect(pair.leaderDriver.getUserKey(USER_A)).toBe(USER_KEY);
    expect(pair.followerDriver.getUserKey(USER_A)).toBe(USER_KEY);

    // The leader reloads and comes back locked with no crypto sessions. The
    // follower is untouched: it stays unlocked and still holds the pre-reload
    // crypto session. Leader (locked) and follower (unlocked) are now out of
    // sync, so a follower unlock event should propagate to the leader.
    const reloaded = await reloadLeader(pair, {
      leader: { initialStates: USER_A_LOCKED_STATE },
    });

    // First contact after the reload is encrypted with the now-stale session.
    // Desired behavior: the unlock still reaches the leader (transparent
    // re-handshake + retry). FAILS today — the reloaded leader replies
    // `CryptoInvalidated` and drops the payload, so the leader stays locked.
    await reloaded.follower.handle_device_event(UNLOCK_EVENT);
    await sleep(50);
    expect(reloaded.leaderDriver.getUserKey(USER_A)).toBe(USER_KEY);
  }, 15000);

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
