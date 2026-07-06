import {
  BiometricsStatus,
  IpcClient,
  ipcRegisterBiometricsHandlers,
  ipcRequestAuthenticateBiometrics,
  ipcRequestGetBiometricsStatus,
  ipcRequestUnlockBiometrics,
  init_sdk,
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
});
