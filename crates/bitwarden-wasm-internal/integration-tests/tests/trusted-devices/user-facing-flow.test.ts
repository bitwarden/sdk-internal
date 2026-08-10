// Registering an account that unlocks by trusted device (TDE).
//
// Registration is the one operation with no second chance: it *chooses* the account's keys, and if it
// emits a state the SDK cannot later load, the account is unrecoverable. So each test registers against
// the model server and then proves the emitted material works by unlocking a brand new client with it.
//
// The shared scaffolding — the harness, the constants and `unlockFreshAndValidate` — lives in
// `tests/registration-support.ts`.

import type { UnsignedSharedKey } from "@bitwarden/sdk-internal";

import {
  assertRegistrationHarnessClean,
  DEVICE_IDENTIFIER,
  newClient,
  organization,
  REGISTRATION_TIMEOUT,
  setupRegistration,
  unlockFreshAndValidate,
  USER_ID,
  type RegistrationHarness,
} from "../registration-support";
import { encstring } from "../utils";

describe("registering an account that unlocks by trusted device (tde)", () => {
  let harness: RegistrationHarness;

  beforeEach(() => {
    harness = setupRegistration();
  });

  afterEach(() => assertRegistrationHarnessClean(harness));

  it(
    "registers a TDE account, and the account unlocks by device key",
    async () => {
      const result = await newClient()
        .auth()
        .registration()
        .post_keys_for_tde_registration({
          org_id: organization.organizationId,
          org_public_key: organization.publicKey,
          user_id: USER_ID,
          device_identifier: DEVICE_IDENTIFIER,
          trust_device: true,
        } as never);

      // The device keys the client posted are the other half of a device-key unlock; the response only
      // carries the device key itself, so the wrapped halves come off the server.
      const deviceKeys = harness.api.deviceKeys(DEVICE_IDENTIFIER);
      if (deviceKeys === undefined) {
        throw new Error(`no device keys recorded for ${DEVICE_IDENTIFIER}`);
      }

      await unlockFreshAndValidate(
        result.account_cryptographic_state,
        {
          deviceKey: {
            device_key: result.device_key,
            protected_device_private_key: encstring(deviceKeys.encryptedPrivateKey),
            device_protected_user_key: deviceKeys.encryptedUserKey as unknown as UnsignedSharedKey,
          },
        },
        result.user_key.toString(),
        { pBKDF2: { iterations: 600_000 } },
      );
    },
    REGISTRATION_TIMEOUT,
  );
});
