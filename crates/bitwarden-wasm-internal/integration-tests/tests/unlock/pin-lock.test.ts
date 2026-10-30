import { PasswordManagerClient, type WasmStateBridge } from "@bitwarden/sdk-internal";
import {
  initializeUserCrypto,
  makeInitializedPasswordmanagerClient,
  makePasswordManagerClient,
  makeStateBridge,
  TEST_PIN,
} from "../utils";

describe("pin lock tests", () => {
  let client: PasswordManagerClient;
  let stateBridge: WasmStateBridge;

  beforeAll(async () => {
    stateBridge = makeStateBridge();
    client = await makeInitializedPasswordmanagerClient(stateBridge);
  });

  it("enrolls a PIN with BeforeFirstUnlock lock type", async () => {
    const pinSettings = client.user_crypto_management().pin_settings();

    await pinSettings.set_pin(TEST_PIN, "BeforeFirstUnlock");

    expect(await pinSettings.get_status()).toEqual("Available");
    expect(await pinSettings.get_lock_type()).toBe("BeforeFirstUnlock");
    expect(await stateBridge.get_encrypted_pin()).toBeDefined();
    // BeforeFirstUnlock populates both envelopes
    expect(await stateBridge.get_persistent_pin_envelope()).toBeDefined();
    expect(await stateBridge.get_ephemeral_pin_envelope()).toBeDefined();
  });

  it("enrolls a PIN with AfterFirstUnlock lock type", async () => {
    const pinSettings = client.user_crypto_management().pin_settings();

    await pinSettings.set_pin(TEST_PIN, "AfterFirstUnlock");

    expect(await pinSettings.get_status()).toEqual("Available");
    expect(await pinSettings.get_lock_type()).toBe("AfterFirstUnlock");
    expect(await stateBridge.get_encrypted_pin()).toBeDefined();
    // AfterFirstUnlock populates only the ephemeral envelope
    expect(await stateBridge.get_ephemeral_pin_envelope()).toBeDefined();
    expect(await stateBridge.get_persistent_pin_envelope()).toBeNull();
  });

  it("validates the PIN", async () => {
    const pinSettings = client.user_crypto_management().pin_settings();

    await pinSettings.set_pin(TEST_PIN, "BeforeFirstUnlock");
    const validated = await pinSettings.validate_pin(TEST_PIN);

    expect(validated).toBe(true);
  });

  it("unsets the PIN", async () => {
    const pinSettings = client.user_crypto_management().pin_settings();

    await pinSettings.set_pin(TEST_PIN, "BeforeFirstUnlock");
    await pinSettings.unset_pin();

    expect(await pinSettings.get_status()).toEqual("NotSet");
    expect(await stateBridge.get_encrypted_pin()).toBeNull();
    expect(await stateBridge.get_persistent_pin_envelope()).toBeNull();
    expect(await stateBridge.get_ephemeral_pin_envelope()).toBeNull();
  });

  it("stores the PIN length on set and clears it on unset", async () => {
    const pinSettings = client.user_crypto_management().pin_settings();

    await pinSettings.set_pin(TEST_PIN, "AfterFirstUnlock");

    expect(await stateBridge.get_pin_length()).toBe(TEST_PIN.length);
    expect(await pinSettings.get_pin_length()).toBe(TEST_PIN.length);

    await pinSettings.unset_pin();

    expect(await stateBridge.get_pin_length()).toBeNull();
    expect(await pinSettings.get_pin_length()).toBeUndefined();
  });

  it("stores the length of a PIN set before lengths were, on unlock", async () => {
    const bridge = makeStateBridge();
    const setupClient = await makeInitializedPasswordmanagerClient(bridge);
    await setupClient
      .user_crypto_management()
      .pin_settings()
      .set_pin(TEST_PIN, "BeforeFirstUnlock");
    // Emulates a PIN set before lengths were stored.
    await bridge.clear_pin_length();

    const unlockedClient = makePasswordManagerClient(bridge);
    await initializeUserCrypto(unlockedClient, { pinState: { pin: TEST_PIN } });

    expect(await unlockedClient.user_crypto_management().pin_settings().get_pin_length()).toBe(
      TEST_PIN.length,
    );
  });
});
