import {
  PasswordManagerClient,
  type WasmStateBridge,
} from "@bitwarden/sdk-internal";
import { makeInitializedPasswordmanagerClient, makeStateBridge, TEST_PIN } from "./utils";

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
});
