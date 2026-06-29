import {
  WasmStateBridge,
  PasswordProtectedKeyEnvelope,
  EncString,
  SymmetricKey,
  V2UpgradeToken,
  WrappedAccountCryptographicState,
  MasterPasswordUnlockData,
  PasswordManagerClient,
  init_sdk,
  TokenProvider,
  UserId,
  IpcClient,
  IpcCommunicationBackend,
  IpcCommunicationBackendSender,
  IncomingMessage,
  OutgoingMessage,
  Source,
  Endpoint,
  Reachability,
  BiometricsUnlock,
  BiometricsStatus,
  SharedUnlockDriver,
  SharedUnlockFollower,
  SharedUnlockLeader,
  InitUserCryptoMethod,
} from "@bitwarden/sdk-internal";
import {
  ORG_ACCOUNT_KDF_PARAMS,
  ORG_ACCOUNT_MASTER_KEY_WRAPPED_USER_KEY,
  ORG_ACCOUNT_PRIVATE_KEY,
  TEST_ORGANIZATION_ID,
  TEST_ORGANIZATION_KEY,
} from "./org-fixtures";

export const encstring = (s: string) => s as unknown as EncString;
const userId = (s: string) => s as unknown as UserId;

/**
 * Makes a simple in-memory implementation of the WasmStateBridge for testing.
 */
export function makeStateBridge(): WasmStateBridge {
  let persistentPinEnvelope: PasswordProtectedKeyEnvelope | null;
  let ephemeralPinEnvelope: PasswordProtectedKeyEnvelope | null;
  let encryptedPin: EncString | null;
  let user_key: SymmetricKey | null;
  let v2UpgradeToken: V2UpgradeToken | null;
  let accountCryptographicState: WrappedAccountCryptographicState | null;
  let masterPasswordUnlockData: MasterPasswordUnlockData | null;

  return {
    set_user_key: async (v: SymmetricKey) => {
      user_key = v;
    },
    get_user_key: async () => user_key,
    clear_user_key: async () => {
      user_key = null;
    },

    set_persistent_pin_envelope: async (v: PasswordProtectedKeyEnvelope) => {
      persistentPinEnvelope = v;
    },
    get_persistent_pin_envelope: async () => persistentPinEnvelope,
    clear_persistent_pin_envelope: async () => {
      persistentPinEnvelope = null;
    },

    set_ephemeral_pin_envelope: async (v: PasswordProtectedKeyEnvelope) => {
      ephemeralPinEnvelope = v;
    },
    get_ephemeral_pin_envelope: async () => ephemeralPinEnvelope,
    clear_ephemeral_pin_envelope: async () => {
      ephemeralPinEnvelope = null;
    },

    set_encrypted_pin: async (v: EncString) => {
      encryptedPin = v;
    },
    get_encrypted_pin: async () => encryptedPin,
    clear_encrypted_pin: async () => {
      encryptedPin = null;
    },

    set_v2_upgrade_token: async (v: V2UpgradeToken) => {
      v2UpgradeToken = v;
    },
    get_v2_upgrade_token: async () => v2UpgradeToken,
    clear_v2_upgrade_token: async () => {
      v2UpgradeToken = null;
    },

    set_account_cryptographic_state: async (v: WrappedAccountCryptographicState) => {
      accountCryptographicState = v;
    },
    get_account_cryptographic_state: async () => accountCryptographicState,
    clear_account_cryptographic_state: async () => {
      accountCryptographicState = null;
    },

    set_masterpassword_unlock_data: async (v: MasterPasswordUnlockData) => {
      masterPasswordUnlockData = v;
    },
    get_masterpassword_unlock_data: async () => masterPasswordUnlockData,
    clear_masterpassword_unlock_data: async () => {
      masterPasswordUnlockData = null;
    },
  };
}

export const TEST_USER_ID = userId("00000000-0000-0000-0000-000000000000");
export const TEST_EMAIL = "test@bitwarden.com";
export const TEST_PASSWORD = "asdfasdfasdf";
export const TEST_PIN = "1234";
export const TEST_KDF_PARAMS = { pBKDF2: { iterations: 100_000 } } as const;
export const PRIVATE_KEY =
  "2.kmLY8NJVuiKBFJtNd/ZFpA==|qOodlRXER+9ogCe3yOibRHmUcSNvjSKhdDuztLlucs10jLiNoVVVAc+9KfNErLSpx5wmUF1hBOJM8zwVPjgQTrmnNf/wuDpwiaCxNYb/0v4FygPy7ccAHK94xP1lfqq7U9+tv+/yiZSwgcT+xF0wFpoxQeNdNRFzPTuD9o4134n8bzacD9DV/WjcrXfRjbBCzzuUGj1e78+A7BWN7/5IWLz87KWk8G7O/W4+8PtEzlwkru6Wd1xO19GYU18oArCWCNoegSmcGn7w7NDEXlwD403oY8Oa7ylnbqGE28PVJx+HLPNIdSC6YKXeIOMnVs7Mctd/wXC93zGxAWD6ooTCzHSPVV50zKJmWIG2cVVUS7j35H3rGDtUHLI+ASXMEux9REZB8CdVOZMzp2wYeiOpggebJy6MKOZqPT1R3X0fqF2dHtRFPXrNsVr1Qt6bS9qTyO4ag1/BCvXF3P1uJEsI812BFAne3cYHy5bIOxuozPfipJrTb5WH35bxhElqwT3y/o/6JWOGg3HLDun31YmiZ2HScAsUAcEkA4hhoTNnqy4O2s3yVbCcR7jF7NLsbQc0MDTbnjxTdI4VnqUIn8s2c9hIJy/j80pmO9Bjxp+LQ9a2hUkfHgFhgHxZUVaeGVth8zG2kkgGdrp5VHhxMVFfvB26Ka6q6qE/UcS2lONSv+4T8niVRJz57qwctj8MNOkA3PTEfe/DP/LKMefke31YfT0xogHsLhDkx+mS8FCc01HReTjKLktk/Jh9mXwC5oKwueWWwlxI935ecn+3I2kAuOfMsgPLkoEBlwgiREC1pM7VVX1x8WmzIQVQTHd4iwnX96QewYckGRfNYWz/zwvWnjWlfcg8kRSe+68EHOGeRtC5r27fWLqRc0HNcjwpgHkI/b6czerCe8+07TWql4keJxJxhBYj3iOH7r9ZS8ck51XnOb8tGL1isimAJXodYGzakwktqHAD7MZhS+P02O+6jrg7d+yPC2ZCuS/3TOplYOCHQIhnZtR87PXTUwr83zfOwAwCyv6KP84JUQ45+DItrXLap7nOVZKQ5QxYIlbThAO6eima6Zu5XHfqGPMNWv0bLf5+vAjIa5np5DJrSwz9no/hj6CUh0iyI+SJq4RGI60lKtypMvF6MR3nHLEHOycRUQbZIyTHWl4QQLdHzuwN9lv10ouTEvNr6sFflAX2yb6w3hlCo7oBytH3rJekjb3IIOzBpeTPIejxzVlh0N9OT5MZdh4sNKYHUoWJ8mnfjdM+L4j5Q2Kgk/XiGDgEebkUxiEOQUdVpePF5uSCE+TPav/9FIRGXGiFn6NJMaU7aBsDTFBLloffFLYDpd8/bTwoSvifkj7buwLYM+h/qcnfdy5FWau1cKav+Blq/ZC0qBpo658RTC8ZtseAFDgXoQZuksM10hpP9bzD04Bx30xTGX81QbaSTNwSEEVrOtIhbDrj9OI43KH4O6zLzK+t30QxAv5zjk10RZ4+5SAdYndIlld9Y62opCfPDzRy3ubdve4ZEchpIKWTQvIxq3T5ogOhGaWBVYnkMtM2GVqvWV//46gET5SH/MdcwhACUcZ9kCpMnWH9CyyUwYvTT3UlNyV+DlS27LMPvaw7tx7qa+GfNCoCBd8S4esZpQYK/WReiS8=|pc7qpD42wxyXemdNPuwxbh8iIaryrBPu8f/DGwYdHTw=";
export const MASTER_KEY_WRAPPED_USER_KEY =
  "2.u2HDQ/nH2J7f5tYHctZx6Q==|NnUKODz8TPycWJA5svexe1wJIz2VexvLbZh2RDfhj5VI3wP8ZkR0Vicvdv7oJRyLI1GyaZDBCf9CTBunRTYUk39DbZl42Rb+Xmzds02EQhc=|rwuo5wgqvTJf3rgwOUfabUyzqhguMYb3sGBjOYqjevc=";

/**
 * Makes an uninitialized password manager client and registers the supplied state bridge.
 */
export function makePasswordManagerClient(stateBridge: WasmStateBridge): PasswordManagerClient {
  init_sdk();

  const tokens: TokenProvider = {
    get_access_token: async () => undefined,
  };

  const client = new PasswordManagerClient(tokens);
  client.km_state_bridge().register_bridge_impl(stateBridge);
  return client;
}

/**
 * Builds a default master-password [`InitUserCryptoRequest`] using the shared test fixtures.
 */
export function initializeCryptoDefault(client: PasswordManagerClient) {
  return client.crypto().initialize_user_crypto({
    userId: TEST_USER_ID,
    kdfParams: TEST_KDF_PARAMS,
    email: TEST_EMAIL,
    accountCryptographicState: { V1: { private_key: encstring(PRIVATE_KEY) } },
    method: {
      masterPasswordUnlock: {
        password: TEST_PASSWORD,
        master_password_unlock: {
          masterKeyWrappedUserKey: encstring(MASTER_KEY_WRAPPED_USER_KEY),
          salt: TEST_EMAIL,
          kdf: TEST_KDF_PARAMS,
        },
      },
    },
  });
}

export function initializeUserCrypto(
  client: PasswordManagerClient,
  initUserCryptoMethod: InitUserCryptoMethod,
) {
  return client.crypto().initialize_user_crypto({
    userId: TEST_USER_ID,
    kdfParams: TEST_KDF_PARAMS,
    email: TEST_EMAIL,
    accountCryptographicState: { V1: { private_key: encstring(PRIVATE_KEY) } },
    method: initUserCryptoMethod,
  });
}

/**
 * Makes a password manager client with an initialized crypto state for testing.
 */
export async function makeInitializedPasswordmanagerClient(
  stateBridge: WasmStateBridge,
): Promise<PasswordManagerClient> {
  const client = makePasswordManagerClient(stateBridge);
  await initializeCryptoDefault(client);
  return client;
}

/**
 * Makes a password manager client initialized with the organization-capable
 * account (see `org-fixtures.ts`) and the organization's key loaded into the
 * key store. This is the setup required for organization-scoped operations
 * such as the invite link client.
 */
export async function makeOrgInitializedClient(
  stateBridge: WasmStateBridge,
): Promise<PasswordManagerClient> {
  const client = makePasswordManagerClient(stateBridge);
  await client.crypto().initialize_user_crypto({
    userId: TEST_USER_ID,
    kdfParams: ORG_ACCOUNT_KDF_PARAMS,
    email: TEST_EMAIL,
    accountCryptographicState: { V1: { private_key: encstring(ORG_ACCOUNT_PRIVATE_KEY) } },
    method: {
      masterPasswordUnlock: {
        password: TEST_PASSWORD,
        master_password_unlock: {
          masterKeyWrappedUserKey: encstring(ORG_ACCOUNT_MASTER_KEY_WRAPPED_USER_KEY),
          salt: TEST_EMAIL,
          kdf: ORG_ACCOUNT_KDF_PARAMS,
        },
      },
    },
  });
  await client.crypto().initialize_org_crypto({
    organizationKeys: new Map([[TEST_ORGANIZATION_ID, TEST_ORGANIZATION_KEY]]),
  });
  return client;
}

/**
 * Hook surface for re-pointing where each side of `makeMockTransportPair`
 * delivers its outgoing messages. Used by `reloadFollower` to attach a fresh
 * follower-side backend to an existing leader.
 */
export interface MockTransportRouter {
  setFirstReceiver(receive: (m: IncomingMessage) => void): void;
  setSecondReceiver(receive: (m: IncomingMessage) => void): void;
  firstSource: Source;
  secondSource: Source;
}

/**
 * Creates two paired in-memory `IpcCommunicationBackend`s for tests. Anything one
 * peer sends is delivered to the other peer's incoming queue, with the
 * sender's `Source` identity. Mirrors `TestTwoWayCommunicationBackend` from the
 * Rust IPC crate.
 */
export function makeMockTransportPair(
  firstSource: Source = "DesktopMain",
  secondSource: Source = "DesktopRenderer",
  reachability?: Reachability,
): [IpcCommunicationBackend, IpcCommunicationBackend, MockTransportRouter] {
  let receiveOnFirst: (m: IncomingMessage) => void;
  let receiveOnSecond: (m: IncomingMessage) => void;

  // When a reachability is given, both senders answer it natively (so the SDK trusts it and skips
  // ping/pong); otherwise the method is absent and the SDK treats the transport as Unsupported.
  const reachabilityMethod = reachability
    ? { reachability: async (_endpoint: Endpoint): Promise<Reachability> => reachability }
    : {};

  const firstSender: IpcCommunicationBackendSender = {
    send: async (outgoing: OutgoingMessage) => {
      receiveOnSecond(
        new IncomingMessage(outgoing.payload, outgoing.destination, firstSource, outgoing.topic),
      );
    },
    ...reachabilityMethod,
  };
  const secondSender: IpcCommunicationBackendSender = {
    send: async (outgoing: OutgoingMessage) => {
      receiveOnFirst(
        new IncomingMessage(outgoing.payload, outgoing.destination, secondSource, outgoing.topic),
      );
    },
    ...reachabilityMethod,
  };

  const first = new IpcCommunicationBackend(firstSender);
  const second = new IpcCommunicationBackend(secondSender);
  receiveOnFirst = (m) => first.receive(m);
  receiveOnSecond = (m) => second.receive(m);

  const router: MockTransportRouter = {
    setFirstReceiver: (fn) => {
      receiveOnFirst = fn;
    },
    setSecondReceiver: (fn) => {
      receiveOnSecond = fn;
    },
    firstSource,
    secondSource,
  };

  return [first, second, router];
}

export function testSymmetricKey(fill: number = 0x42): SymmetricKey {
  return Buffer.alloc(64, fill).toString("base64") as unknown as SymmetricKey;
}

/**
 * Configuration options for the in-memory biometrics driver.
 */
export interface MockBiometricsDriverOptions {
  status: BiometricsStatus;
  userKey: SymmetricKey | undefined;
  uvResult: boolean;
}

/**
 * In-memory implementation of the `BiometricsUnlock` JS interface for tests.
 */
export function makeMockBiometricsDriver(
  options: MockBiometricsDriverOptions = {
    status: BiometricsStatus.Available,
    userKey: testSymmetricKey(),
    uvResult: true,
  },
): BiometricsUnlock {
  return {
    get_biometrics_status: async () => options.status,
    unlock_biometrics: async () => options.userKey,
    authenticate_biometrics: async () => options.uvResult,
  };
}

/**
 * Options for the in-memory shared-unlock driver.
 */
export interface MockSharedUnlockDriverOptions {
  initialStates?: Map<UserId, SymmetricKey | undefined>;
  clientName?: "web" | "browser" | "cli" | "desktop";
  vaultUrls?: Map<UserId, string>;
}

/**
 * Mock shared-unlock driver plus inspection helpers.
 */
export interface MockSharedUnlockDriverHandle {
  driver: SharedUnlockDriver;
  getUserKey(user_id: UserId): SymmetricKey | undefined;
  suppressedTimeouts: Array<{ user_id: UserId; duration_ms: number }>;
}

/**
 * In-memory implementation of the `SharedUnlockDriver` JS interface for tests.
 * Lock/unlock calls mutate the same in-memory state that `get_user_key` reads,
 * so the driver reflects whatever the protocol last did to it.
 */
export function makeMockSharedUnlockDriver(
  options: MockSharedUnlockDriverOptions = {},
): MockSharedUnlockDriverHandle {
  const states = new Map(options.initialStates ?? []);
  const vaultUrls = new Map(options.vaultUrls ?? []);
  const clientName = options.clientName ?? "browser";
  const suppressedTimeouts: Array<{ user_id: UserId; duration_ms: number }> = [];

  const driver: SharedUnlockDriver = {
    lock_user: async (user_id) => {
      states.set(user_id, undefined);
    },
    unlock_user: async (user_id, user_key) => {
      states.set(user_id, user_key);
    },
    list_users: async () => Array.from(states.keys()),
    get_user_key: async (user_id) => states.get(user_id) ?? undefined,
    suppress_vault_timeout: async (user_id, suppression_duration) => {
      suppressedTimeouts.push({ user_id, duration_ms: suppression_duration });
    },
    get_client_name: async () => clientName,
    get_vault_url: async (user_id) => vaultUrls.get(user_id),
  };

  return {
    driver,
    getUserKey: (user_id) => states.get(user_id) ?? undefined,
    suppressedTimeouts,
  };
}

export async function sleep(ms: number): Promise<void> {
  for (let elapsed = 0; elapsed < ms; elapsed += 1) {
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
}

/**
 * Wires up a `SharedUnlockLeader` and `SharedUnlockFollower` over a paired
 * in-memory IPC transport. The leader is started before the follower, so the
 * leader has subscribed to `FollowerMessage` before the follower's
 * `start_sessions` sends its first `StartSession`.
 *
 * Both `start()` calls run background loops that only exit when their abort
 * controllers fire — call `cleanup()` (or the returned controllers) at the
 * end of each test to terminate them.
 */
export interface SharedUnlockPair {
  leader: SharedUnlockLeader;
  follower: SharedUnlockFollower;
  leaderDriver: MockSharedUnlockDriverHandle;
  followerDriver: MockSharedUnlockDriverHandle;
  leaderAbort: AbortController;
  followerAbort: AbortController;
  _internal: {
    router: MockTransportRouter;
    leaderBackend: IpcCommunicationBackend;
    followerBackend: IpcCommunicationBackend;
    followerSource: Source;
    leaderSource: Source;
  };
}

export async function setupSharedUnlockPair(options: {
  leader: MockSharedUnlockDriverOptions;
  follower: MockSharedUnlockDriverOptions;
}): Promise<SharedUnlockPair> {
  init_sdk();

  // First peer = follower (sends to DesktopRenderer = leader's endpoint).
  // Second peer = leader (replies to DesktopMain = follower's source).
  const followerSource: Source = "DesktopMain";
  const leaderSource: Source = "DesktopRenderer";
  // The leader is genuinely present in these tests, so the transport reports Reachable and the
  // follower's reachability gating passes immediately (no ping/pong round trip needed). The
  // ping/pong fallback path is covered by reachability-ipc.test.ts.
  const [followerBackend, leaderBackend, router] = makeMockTransportPair(
    followerSource,
    leaderSource,
    "Reachable",
  );

  const leaderIpc = IpcClient.newWithSdkInMemorySessions(leaderBackend);
  const followerIpc = IpcClient.newWithSdkInMemorySessions(followerBackend);

  await leaderIpc.start();
  await followerIpc.start();

  const leaderDriver = makeMockSharedUnlockDriver(options.leader);
  const followerDriver = makeMockSharedUnlockDriver(options.follower);

  const leader = SharedUnlockLeader.try_new(leaderIpc, leaderDriver.driver);
  const follower = SharedUnlockFollower.try_new(followerIpc, followerDriver.driver);

  // Start the leader first so it has subscribed before the follower sends
  // its initial `StartSession` messages.
  const leaderAbort = new AbortController();
  const followerAbort = new AbortController();
  await leader.start(leaderAbort);
  await follower.start(followerAbort);

  return {
    leader,
    follower,
    leaderDriver,
    followerDriver,
    leaderAbort,
    followerAbort,
    _internal: {
      router,
      leaderBackend,
      followerBackend,
      followerSource,
      leaderSource,
    },
  };
}

/**
 * Simulates a follower process reload: the old follower's background loops
 * are aborted, then a brand-new `IpcCommunicationBackend`, `IpcClient`,
 * driver, and `SharedUnlockFollower` are attached to the same leader. The
 * new follower stamps the same `Source` on outgoing messages so the leader's
 * session tracking treats it as the same endpoint coming back online.
 */
export async function reloadFollower(
  pair: SharedUnlockPair,
  options: { follower: MockSharedUnlockDriverOptions },
): Promise<SharedUnlockPair> {
  pair.followerAbort.abort();

  const { router, leaderBackend, followerSource } = pair._internal;

  const newFollowerSender: IpcCommunicationBackendSender = {
    send: async (outgoing: OutgoingMessage) => {
      leaderBackend.receive(
        new IncomingMessage(outgoing.payload, outgoing.destination, followerSource, outgoing.topic),
      );
    },
    reachability: async (_endpoint: Endpoint): Promise<Reachability> => "Reachable",
  };
  const newFollowerBackend = new IpcCommunicationBackend(newFollowerSender);

  router.setFirstReceiver((m) => newFollowerBackend.receive(m));

  const newFollowerIpc = IpcClient.newWithSdkInMemorySessions(newFollowerBackend);
  await newFollowerIpc.start();

  const newFollowerDriver = makeMockSharedUnlockDriver(options.follower);
  const newFollower = SharedUnlockFollower.try_new(newFollowerIpc, newFollowerDriver.driver);

  const newFollowerAbort = new AbortController();
  await newFollower.start(newFollowerAbort);

  return {
    ...pair,
    follower: newFollower,
    followerDriver: newFollowerDriver,
    followerAbort: newFollowerAbort,
  };
}

/**
 * Simulates a leader process reload: the old leader's background loops are
 * aborted, then a brand-new `IpcCommunicationBackend`, `IpcClient`, driver,
 * and `SharedUnlockLeader` are attached to the same follower. The new leader
 * stamps the same `Source` on outgoing messages so the follower's session
 * tracking treats it as the same endpoint coming back online.
 *
 * The new leader does not proactively contact the follower — the follower
 * must send something (a device event or, eventually, a heartbeat) for the
 * new leader to learn about the session.
 */
export async function reloadLeader(
  pair: SharedUnlockPair,
  options: { leader: MockSharedUnlockDriverOptions },
): Promise<SharedUnlockPair> {
  pair.leaderAbort.abort();

  const { router, followerBackend, leaderSource } = pair._internal;

  const newLeaderSender: IpcCommunicationBackendSender = {
    send: async (outgoing: OutgoingMessage) => {
      followerBackend.receive(
        new IncomingMessage(outgoing.payload, outgoing.destination, leaderSource, outgoing.topic),
      );
    },
  };
  const newLeaderBackend = new IpcCommunicationBackend(newLeaderSender);

  router.setSecondReceiver((m) => newLeaderBackend.receive(m));

  const newLeaderIpc = IpcClient.newWithSdkInMemorySessions(newLeaderBackend);
  await newLeaderIpc.start();

  const newLeaderDriver = makeMockSharedUnlockDriver(options.leader);
  const newLeader = SharedUnlockLeader.try_new(newLeaderIpc, newLeaderDriver.driver);

  const newLeaderAbort = new AbortController();
  await newLeader.start(newLeaderAbort);

  return {
    ...pair,
    leader: newLeader,
    leaderDriver: newLeaderDriver,
    leaderAbort: newLeaderAbort,
    _internal: {
      ...pair._internal,
      leaderBackend: newLeaderBackend,
    },
  };
}
