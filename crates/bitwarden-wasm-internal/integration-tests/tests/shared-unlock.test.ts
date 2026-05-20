import { UserId } from "@bitwarden/sdk-internal";
import { sleep, setupSharedUnlockPair, testSymmetricKey, MockSharedUnlockDriverHandle } from "./utils";

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
});
