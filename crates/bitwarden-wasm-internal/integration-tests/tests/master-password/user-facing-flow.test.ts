// Creating an account that unlocks by master password, the two ways a user arrives at one: signing up
// directly, and being provisioned into an organization at first sign-in.
//
// Registration is the one operation with no second chance: it *chooses* the account's keys, and if it
// emits a state the SDK cannot later load, the account is unrecoverable. So each test registers against
// the model server and then proves the emitted material works by unlocking a brand new client with it.
//
// The shared scaffolding — the harness, the constants and `unlockFreshAndValidate` — lives in
// `tests/registration-support.ts`.

import type { B64, JitMasterPasswordRegistrationRequest } from "@bitwarden/sdk-internal";

import {
  assertRegistrationHarnessClean,
  EMAIL,
  newClient,
  organization,
  PASSWORD,
  passwordRegistrationRequest,
  REGISTRATION_TIMEOUT,
  setupRegistration,
  unlockFreshAndValidate,
  USER_ID,
  type RegistrationHarness,
} from "../registration-support";

describe("registering an account that unlocks by master password", () => {
  let harness: RegistrationHarness;

  beforeEach(() => {
    harness = setupRegistration();
  });

  afterEach(() => assertRegistrationHarnessClean(harness));

  it(
    "registers a master-password account, and the account unlocks by master password",
    async () => {
      const result = await newClient()
        .auth()
        .registration()
        .post_keys_for_user_password_registration(passwordRegistrationRequest);

      const kdf = result.master_password_unlock.kdf;

      // Unlock a fresh client through the method registration enrolled.
      await unlockFreshAndValidate(
        result.account_cryptographic_state,
        {
          masterPasswordUnlock: {
            password: PASSWORD,
            master_password_unlock: result.master_password_unlock,
          },
        },
        result.user_key.toString(),
        kdf,
      );

      // And the same account is reachable from the returned decrypted key, which is what a client that
      // stays unlocked straight after registering uses.
      await unlockFreshAndValidate(
        result.account_cryptographic_state,
        { decryptedKey: { decrypted_user_key: result.user_key } },
        result.user_key.toString(),
        kdf,
      );
    },
    REGISTRATION_TIMEOUT,
  );

  it(
    "registers a just-in-time master-password account into an organization",
    async () => {
      const result = await newClient()
        .auth()
        .registration()
        .post_keys_for_jit_password_registration({
          org_id: organization.organizationId,
          org_public_key: organization.publicKey as B64,
          organization_sso_identifier: "sso-identifier",
          user_id: USER_ID,
          salt: EMAIL,
          master_password: PASSWORD,
          master_password_hint: undefined,
          reset_password_enroll: true,
        } satisfies JitMasterPasswordRegistrationRequest);

      // `reset_password_enroll: true` must actually enroll the user for admin recovery.
      expect(harness.api.resetPasswordEnrollments()).toEqual([
        `${organization.organizationId}/${USER_ID}`,
      ]);

      await unlockFreshAndValidate(
        result.account_cryptographic_state,
        {
          masterPasswordUnlock: {
            password: PASSWORD,
            master_password_unlock: result.master_password_unlock,
          },
        },
        result.user_key.toString(),
        result.master_password_unlock.kdf,
      );
    },
    REGISTRATION_TIMEOUT,
  );
});
