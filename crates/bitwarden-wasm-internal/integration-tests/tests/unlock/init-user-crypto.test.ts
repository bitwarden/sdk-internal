import {
  initializeCryptoDefault,
  initializeUserCrypto,
  makePasswordManagerClient,
  makeStateBridge,
  MASTER_KEY_WRAPPED_USER_KEY,
  TEST_EMAIL,
  TEST_KDF_PARAMS,
  TEST_PASSWORD,
  TEST_PIN,
} from "../utils";

const encstring = (s: string) => s as unknown as never;

describe("user crypto initialization tests", () => {
  it("initializes the user account via master password", async () => {
    const stateBridge = makeStateBridge();
    const client = makePasswordManagerClient(stateBridge);

    initializeUserCrypto(client, {
      masterPasswordUnlock: {
        password: TEST_PASSWORD,
        master_password_unlock: {
          masterKeyWrappedUserKey: encstring(MASTER_KEY_WRAPPED_USER_KEY),
          salt: TEST_EMAIL,
          kdf: TEST_KDF_PARAMS,
        },
      },
    });

    expect(await client.crypto().get_user_encryption_key()).toBeDefined();
  });

  it("initializes the user account via PIN Envelope", async () => {
    // Set up a PIN with BeforeFirstUnlock so the persistent envelope is written to the bridge.
    const stateBridge = makeStateBridge();
    const setupClient = makePasswordManagerClient(stateBridge);
    await initializeCryptoDefault(setupClient);

    await setupClient
      .user_crypto_management()
      .pin_settings()
      .set_pin(TEST_PIN, "BeforeFirstUnlock");

    const pinEnvelope = await stateBridge.get_persistent_pin_envelope();
    expect(pinEnvelope).toBeDefined();

    // Now make a new client and initialize with the PIN envelope.
    const client = makePasswordManagerClient(stateBridge);
    await initializeUserCrypto(client, {
      pinEnvelope: { pin: TEST_PIN, pin_protected_user_key_envelope: pinEnvelope! },
    });

    expect(await client.crypto().get_user_encryption_key()).toBeDefined();
  });

  it("initializes the user account via PIN State", async () => {
    // Set up a PIN with BeforeFirstUnlock so the persistent envelope is written to the bridge.
    const stateBridge = makeStateBridge();
    const setupClient = makePasswordManagerClient(stateBridge);
    initializeCryptoDefault(setupClient);

    await setupClient
      .user_crypto_management()
      .pin_settings()
      .set_pin(TEST_PIN, "BeforeFirstUnlock");

    const pinState = await stateBridge.get_encrypted_pin();
    expect(pinState).toBeDefined();

    // Now make a new client and initialize with the PIN state.
    const client = makePasswordManagerClient(stateBridge);
    await initializeUserCrypto(client, { pinState: { pin: TEST_PIN } });

    expect(await client.crypto().get_user_encryption_key()).toBeDefined();
  });
});
