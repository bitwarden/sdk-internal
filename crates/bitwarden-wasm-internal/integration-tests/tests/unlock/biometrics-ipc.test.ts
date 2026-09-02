import {
  BiometricsStatus,
  IpcClient,
  ipcRegisterBiometricsHandlers,
  ipcRequestAuthenticateBiometrics,
  ipcRequestGetBiometricsStatus,
  ipcRequestUnlockBiometrics,
  init_sdk,
  SymmetricKey,
} from "@bitwarden/sdk-internal";
import {
  makeMockBiometricsDriver,
  makeMockTransportPair,
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

  it("does not fail an in-flight unlock when a concurrent status response arrives", async () => {
    const userKey = testSymmetricKey(0x37);
    let releaseUnlock!: (key: SymmetricKey | undefined) => void;
    const unlockGate = new Promise<SymmetricKey | undefined>((resolve) => {
      releaseUnlock = resolve;
    });

    const { requester } = await setupClientPair({
      get_biometrics_status: async () => BiometricsStatus.Available,
      // Stays pending until the test releases it, so the unlock request is
      // guaranteed to still be in flight below.
      unlock_biometrics: () => unlockGate,
      authenticate_biometrics: async () => true,
    });

    // Capture the unlock's settled state without awaiting it, so that if the concurrent status
    // request below were to settle the unlock early, it surfaces as a failed assertion rather than
    // an unhandled rejection.
    const unlock = ipcRequestUnlockBiometrics(requester, TEST_USER_ID).then(
      (ok) => ({ ok }),
      (err) => ({ err: String(err) }),
    );

    // A status request completes while the unlock is still in flight. Its response is delivered
    // only to that request's own response topic, so it must leave the pending unlock untouched.
    await expect(ipcRequestGetBiometricsStatus(requester, TEST_USER_ID)).resolves.toBe(
      BiometricsStatus.Available,
    );

    releaseUnlock(userKey);

    expect(await unlock).toEqual({ ok: { user_key: userKey } });
  });
});
