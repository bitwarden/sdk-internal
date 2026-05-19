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
  InitUserCryptoRequest,
  UserId,
  IpcCommunicationBackend,
  IpcCommunicationBackendSender,
  IncomingMessage,
  OutgoingMessage,
  Source,
  BiometricsUnlock,
  BiometricsStatus,
} from "@bitwarden/sdk-internal";

const encstring = (s: string) => s as unknown as EncString;
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
export const PRIVATE_KEY =
  "2.kmLY8NJVuiKBFJtNd/ZFpA==|qOodlRXER+9ogCe3yOibRHmUcSNvjSKhdDuztLlucs10jLiNoVVVAc+9KfNErLSpx5wmUF1hBOJM8zwVPjgQTrmnNf/wuDpwiaCxNYb/0v4FygPy7ccAHK94xP1lfqq7U9+tv+/yiZSwgcT+xF0wFpoxQeNdNRFzPTuD9o4134n8bzacD9DV/WjcrXfRjbBCzzuUGj1e78+A7BWN7/5IWLz87KWk8G7O/W4+8PtEzlwkru6Wd1xO19GYU18oArCWCNoegSmcGn7w7NDEXlwD403oY8Oa7ylnbqGE28PVJx+HLPNIdSC6YKXeIOMnVs7Mctd/wXC93zGxAWD6ooTCzHSPVV50zKJmWIG2cVVUS7j35H3rGDtUHLI+ASXMEux9REZB8CdVOZMzp2wYeiOpggebJy6MKOZqPT1R3X0fqF2dHtRFPXrNsVr1Qt6bS9qTyO4ag1/BCvXF3P1uJEsI812BFAne3cYHy5bIOxuozPfipJrTb5WH35bxhElqwT3y/o/6JWOGg3HLDun31YmiZ2HScAsUAcEkA4hhoTNnqy4O2s3yVbCcR7jF7NLsbQc0MDTbnjxTdI4VnqUIn8s2c9hIJy/j80pmO9Bjxp+LQ9a2hUkfHgFhgHxZUVaeGVth8zG2kkgGdrp5VHhxMVFfvB26Ka6q6qE/UcS2lONSv+4T8niVRJz57qwctj8MNOkA3PTEfe/DP/LKMefke31YfT0xogHsLhDkx+mS8FCc01HReTjKLktk/Jh9mXwC5oKwueWWwlxI935ecn+3I2kAuOfMsgPLkoEBlwgiREC1pM7VVX1x8WmzIQVQTHd4iwnX96QewYckGRfNYWz/zwvWnjWlfcg8kRSe+68EHOGeRtC5r27fWLqRc0HNcjwpgHkI/b6czerCe8+07TWql4keJxJxhBYj3iOH7r9ZS8ck51XnOb8tGL1isimAJXodYGzakwktqHAD7MZhS+P02O+6jrg7d+yPC2ZCuS/3TOplYOCHQIhnZtR87PXTUwr83zfOwAwCyv6KP84JUQ45+DItrXLap7nOVZKQ5QxYIlbThAO6eima6Zu5XHfqGPMNWv0bLf5+vAjIa5np5DJrSwz9no/hj6CUh0iyI+SJq4RGI60lKtypMvF6MR3nHLEHOycRUQbZIyTHWl4QQLdHzuwN9lv10ouTEvNr6sFflAX2yb6w3hlCo7oBytH3rJekjb3IIOzBpeTPIejxzVlh0N9OT5MZdh4sNKYHUoWJ8mnfjdM+L4j5Q2Kgk/XiGDgEebkUxiEOQUdVpePF5uSCE+TPav/9FIRGXGiFn6NJMaU7aBsDTFBLloffFLYDpd8/bTwoSvifkj7buwLYM+h/qcnfdy5FWau1cKav+Blq/ZC0qBpo658RTC8ZtseAFDgXoQZuksM10hpP9bzD04Bx30xTGX81QbaSTNwSEEVrOtIhbDrj9OI43KH4O6zLzK+t30QxAv5zjk10RZ4+5SAdYndIlld9Y62opCfPDzRy3ubdve4ZEchpIKWTQvIxq3T5ogOhGaWBVYnkMtM2GVqvWV//46gET5SH/MdcwhACUcZ9kCpMnWH9CyyUwYvTT3UlNyV+DlS27LMPvaw7tx7qa+GfNCoCBd8S4esZpQYK/WReiS8=|pc7qpD42wxyXemdNPuwxbh8iIaryrBPu8f/DGwYdHTw=";
export const MASTER_KEY_WRAPPED_USER_KEY =
  "2.u2HDQ/nH2J7f5tYHctZx6Q==|NnUKODz8TPycWJA5svexe1wJIz2VexvLbZh2RDfhj5VI3wP8ZkR0Vicvdv7oJRyLI1GyaZDBCf9CTBunRTYUk39DbZl42Rb+Xmzds02EQhc=|rwuo5wgqvTJf3rgwOUfabUyzqhguMYb3sGBjOYqjevc=";

/**
 * Makes a password manager client with an initialized crypto state for testing.
 */
export async function makeInitializedPasswordmanagerClient(
  stateBridge: WasmStateBridge,
): Promise<PasswordManagerClient> {
  init_sdk();

  const tokens: TokenProvider = {
    get_access_token: async () => undefined,
  };

  const client = new PasswordManagerClient(tokens);
  client.km_state_bridge().register_bridge_impl(stateBridge);

  const req: InitUserCryptoRequest = {
    userId: userId("00000000-0000-0000-0000-000000000000"),
    kdfParams: { pBKDF2: { iterations: 100_000 } },
    email: TEST_EMAIL,
    accountCryptographicState: { V1: { private_key: encstring(PRIVATE_KEY) } },
    method: {
      masterPasswordUnlock: {
        password: TEST_PASSWORD,
        master_password_unlock: {
          kdf: { pBKDF2: { iterations: 100_000 } },
          masterKeyWrappedUserKey: encstring(MASTER_KEY_WRAPPED_USER_KEY),
          salt: TEST_EMAIL,
        },
      },
    },
  };

  await client.crypto().initialize_user_crypto(req);
  return client;
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
): [IpcCommunicationBackend, IpcCommunicationBackend] {
  // We need each sender to reference the *other* peer's backend, but the
  // backends don't exist until after their senders are constructed. The
  // forwarder closures capture mutable slots that we fill in below.
  let deliverToSecond: ((m: OutgoingMessage) => Promise<void>) | null = null;
  let deliverToFirst: ((m: OutgoingMessage) => Promise<void>) | null = null;

  const firstSender: IpcCommunicationBackendSender = {
    send: async (message: OutgoingMessage) => {
      await deliverToSecond!(message);
    },
  };
  const secondSender: IpcCommunicationBackendSender = {
    send: async (message: OutgoingMessage) => {
      await deliverToFirst!(message);
    },
  };

  const first = new IpcCommunicationBackend(firstSender);
  const second = new IpcCommunicationBackend(secondSender);

  deliverToSecond = async (outgoing) => {
    second.receive(
      new IncomingMessage(outgoing.payload, outgoing.destination, firstSource, outgoing.topic),
    );
  };
  deliverToFirst = async (outgoing) => {
    first.receive(
      new IncomingMessage(outgoing.payload, outgoing.destination, secondSource, outgoing.topic),
    );
  };

  return [first, second];
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
