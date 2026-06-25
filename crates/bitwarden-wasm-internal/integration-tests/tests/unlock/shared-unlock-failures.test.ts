import { Endpoint, UserId } from "@bitwarden/sdk-internal";
import { sleep, setupSharedUnlockPair, setupSharedUnlockHub, testSymmetricKey } from "../utils";

const USER_A = "00000000-0000-0000-0000-000000000001" as unknown as UserId;
const USER_KEY = testSymmetricKey(0x11);
const USER_A_LOCKED_STATE = new Map([[USER_A, undefined]]);
const USER_A_UNLOCKED_STATE = new Map([[USER_A, USER_KEY]]);
const UNLOCK_EVENT = { ManualUnlock: { user_id: USER_A, user_key: USER_KEY } };
const LOCK_EVENT = { ManualLock: { user_id: USER_A } };

/** Polls `predicate` until it is true or the timeout elapses. */
async function waitFor(predicate: () => boolean, timeoutMs: number): Promise<boolean> {
  const step = 20;
  for (let elapsed = 0; elapsed < timeoutMs; elapsed += step) {
    if (predicate()) {
      return true;
    }
    await sleep(step);
  }
  return predicate();
}

/** Polls an async `predicate` until it resolves true or the timeout elapses. */
async function waitForAsync(
  predicate: () => Promise<boolean>,
  timeoutMs: number,
): Promise<boolean> {
  const step = 20;
  for (let elapsed = 0; elapsed < timeoutMs; elapsed += step) {
    if (await predicate()) {
      return true;
    }
    await sleep(step);
  }
  return predicate();
}

// These tests exercise partial-connectivity failure modes: a follower that is still in the leader's
// session map but temporarily cannot receive messages. The recovery mechanism under test is the
// authoritative `LockStateUpdate` the leader piggybacks on every heartbeat response — the only
// desync-repair path, since sends are fire-and-forget.
//
// NOTE: `handle_device_event` only *broadcasts*; it does not mutate the caller's own driver (in a
// real client the app already changed its own lock state and is merely notifying peers). The
// per-heartbeat authoritative update reads the leader driver's state, so each test first drives the
// leader's mock driver to the state it is about to announce — otherwise the heartbeat would revert
// the followers right back.
describe("shared unlock failure cases", () => {
  it("re-locks a follower that missed the leader's Lock broadcast while its downlink was down", async () => {
    const pair = await setupSharedUnlockPair({
      leader: { initialStates: USER_A_UNLOCKED_STATE },
      follower: { initialStates: USER_A_UNLOCKED_STATE },
    });
    await sleep(50);
    expect(pair.followerDriver.getUserKey(USER_A)).toBe(USER_KEY);

    // The leader->follower downlink dies: the follower can no longer receive broadcasts or
    // heartbeat responses, but its own heartbeats still reach the leader.
    pair._internal.router.setLinkUp("secondToFirst", false);

    // The leader locks. The broadcast `LockStateUpdate{Locked}` is dropped on the dead downlink.
    await pair.leaderDriver.driver.lock_user(USER_A);
    await pair.leader.handle_device_event(LOCK_EVENT);
    await sleep(200);
    expect(pair.followerDriver.getUserKey(USER_A)).toBe(USER_KEY); // missed the lock, still unlocked

    // Restore the downlink. The next heartbeat carries the authoritative locked state and the
    // follower re-locks.
    pair._internal.router.setLinkUp("secondToFirst", true);
    expect(await waitFor(() => pair.followerDriver.getUserKey(USER_A) === undefined, 6000)).toBe(
      true,
    );

    pair.leaderAbort.abort();
    pair.followerAbort.abort();
  }, 15000);

  it("stops talking to an unreachable leader and resyncs once it returns", async () => {
    // The follower discovers `DesktopRenderer` as its leader, so gate (and ping) that endpoint.
    const leaderEndpoint: Endpoint = "DesktopRenderer";
    const pair = await setupSharedUnlockPair({
      leader: { initialStates: USER_A_UNLOCKED_STATE },
      follower: { initialStates: USER_A_UNLOCKED_STATE, pingTargets: [leaderEndpoint] },
    });
    const { followerIpc, router } = pair._internal;

    // A gated leader is unreachable until the ping/pong round trip lands.
    expect(await waitForAsync(() => followerIpc.isReachable(leaderEndpoint), 6000)).toBe(true);
    await sleep(50);
    expect(pair.followerDriver.getUserKey(USER_A)).toBe(USER_KEY);

    // Cut the downlink (no more pongs) and surface the disconnect immediately rather than waiting
    // out the activity window.
    router.setLinkUp("secondToFirst", false);
    followerIpc.invalidateReachability(leaderEndpoint);
    expect(await followerIpc.isReachable(leaderEndpoint)).toBe(false);

    // The leader locks while the follower is unreachable; nothing reaches the follower, and the
    // follower suppresses its own heartbeats against the absent leader.
    await pair.leaderDriver.driver.lock_user(USER_A);
    await pair.leader.handle_device_event(LOCK_EVENT);
    await sleep(200);
    expect(pair.followerDriver.getUserKey(USER_A)).toBe(USER_KEY);

    // Heal the downlink: pings are answered again → reachable → heartbeats resume → the
    // authoritative locked state is applied.
    router.setLinkUp("secondToFirst", true);
    expect(await waitForAsync(() => followerIpc.isReachable(leaderEndpoint), 12000)).toBe(true);
    expect(await waitFor(() => pair.followerDriver.getUserKey(USER_A) === undefined, 6000)).toBe(
      true,
    );

    pair.leaderAbort.abort();
    pair.followerAbort.abort();
  }, 25000);

  it("fans a state change out to every follower and resyncs one whose downlink was down", async () => {
    const hub = await setupSharedUnlockHub({
      leader: { initialStates: USER_A_LOCKED_STATE },
      followers: [{ initialStates: USER_A_LOCKED_STATE }, { initialStates: USER_A_LOCKED_STATE }],
    });
    const [followerA, followerB] = hub.followers;
    await sleep(100); // let both followers' StartSession register on the leader

    // Unlock fans out to both followers.
    await hub.leaderDriver.driver.unlock_user(USER_A, USER_KEY);
    await hub.leader.handle_device_event(UNLOCK_EVENT);
    expect(await waitFor(() => followerA.driver.getUserKey(USER_A) === USER_KEY, 4000)).toBe(true);
    expect(await waitFor(() => followerB.driver.getUserKey(USER_A) === USER_KEY, 4000)).toBe(true);

    // Drop follower B's downlink, then lock. A locks from the broadcast; B never receives it.
    hub.hub.setDownlinkUp(1, false);
    await hub.leaderDriver.driver.lock_user(USER_A);
    await hub.leader.handle_device_event(LOCK_EVENT);
    expect(await waitFor(() => followerA.driver.getUserKey(USER_A) === undefined, 4000)).toBe(true);
    await sleep(200);
    expect(followerB.driver.getUserKey(USER_A)).toBe(USER_KEY); // B missed the lock, still unlocked

    // Heal B's downlink: its heartbeat pulls the authoritative locked state.
    hub.hub.setDownlinkUp(1, true);
    expect(await waitFor(() => followerB.driver.getUserKey(USER_A) === undefined, 6000)).toBe(true);

    hub.leaderAbort.abort();
    hub.followers.forEach((f) => f.abort.abort());
  }, 15000);
});
