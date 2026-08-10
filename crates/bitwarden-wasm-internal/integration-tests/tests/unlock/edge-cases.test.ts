// Two unlock situations worth pinning down: a credential that must be refused, and the one account in
// the set that is caught mid-upgrade between security versions.
//
// The mid-upgrade account is the interesting one. Its master-password unlock data still wraps the *V1*
// user key, while its vault is already blob-encrypted under the V2 key, so opening it requires the
// upgrade token to be consumed during unlock. An account in this state is transient in production and
// easy to break without noticing, which is why the set carries one permanently.

import type { InitUserCryptoMethod } from "@bitwarden/sdk-internal";

import { userVector, type UserVector } from "../test-vectors/load";
import { unlockVector } from "../test-vectors/unlock";
import {
  CHEAPEST_VECTOR,
  UNLOCK_TIMEOUT,
  unlockWithOrganizations,
  validateVectorDirectly,
  vectors,
} from "./unlock-support";

type MasterPasswordMethod = Extract<InitUserCryptoMethod, { masterPasswordUnlock: unknown }>;

/** Picks a vector's master-password method, failing loudly if it has none. */
function masterPasswordMethod(vector: UserVector): MasterPasswordMethod {
  const method = vector.unlockMethods.find((m) => "masterPasswordUnlock" in m);
  if (method === undefined) {
    throw new Error(`${vector.name} declares no masterPasswordUnlock method`);
  }
  return method as MasterPasswordMethod;
}

/**
 * Corrupts one byte of an `EncString`'s ciphertext, leaving its structure untouched.
 *
 * An `Aes256CbcHmac` string is `2.<iv>|<ciphertext>|<mac>`. Flipping a character at the *start* of the
 * ciphertext segment matters: base64 padding only ever appears at the end of a segment, so editing the
 * front cannot change any decoded length, and the string still parses. The MAC then fails, which is the
 * behaviour under test.
 */
function tamperCiphertext(text: string): string {
  const dot = text.indexOf(".");
  expect(dot).toBeGreaterThan(0);

  const parts = text.slice(dot + 1).split("|");
  expect(parts).toHaveLength(3);

  const ciphertext = parts[1];
  parts[1] = (ciphertext[0] === "A" ? "B" : "A") + ciphertext.slice(1);

  return text.slice(0, dot + 1) + parts.join("|");
}

describe("rejecting bad credentials", () => {
  const vector = userVector(vectors, CHEAPEST_VECTOR);

  it(
    "refuses a master password that is not the account's",
    async () => {
      const method = structuredClone(masterPasswordMethod(vector));
      method.masterPasswordUnlock.password = "not-the-password";

      await expect(unlockVector(vector, method)).rejects.toBeDefined();
    },
    UNLOCK_TIMEOUT,
  );

  it(
    "refuses a master password unlock whose wrapped user key has been tampered with",
    async () => {
      const method = structuredClone(masterPasswordMethod(vector));
      const wrapped = method.masterPasswordUnlock.master_password_unlock.masterKeyWrappedUserKey;

      const text = wrapped.toString();
      const tampered = tamperCiphertext(text);
      method.masterPasswordUnlock.master_password_unlock.masterKeyWrappedUserKey =
        tampered as unknown as typeof wrapped;

      // The failure must come from the MAC check, not from a malformed EncString — otherwise this
      // would pass just as happily against a build that skipped authentication entirely.
      expect(tampered).not.toBe(text);
      expect(tampered).toHaveLength(text.length);

      await expect(unlockVector(vector, method)).rejects.toBeDefined();
    },
    UNLOCK_TIMEOUT,
  );
});

describe("the mid-upgrade account", () => {
  const vector = vectors.find((v) => v.name === "v2-argon2id-upgrade-token")!;

  it("exists and carries an upgrade token", () => {
    expect(vector.account.upgradeToken).toBeDefined();
    expect(vector.account.securityVersion).toBe(2);
  });

  it("still wraps the V1 user key in its master-password unlock data", () => {
    const method = vector.unlockMethods.find((m) => "masterPasswordUnlock" in m) as Extract<
      InitUserCryptoMethod,
      { masterPasswordUnlock: unknown }
    >;

    // `2.` is AES-256-CBC-HMAC, the V1 user key. A plain V2 account would carry `7.` here.
    expect(
      method.masterPasswordUnlock.master_password_unlock.masterKeyWrappedUserKey.toString(),
    ).toMatch(/^2\./);
    // The token carries the V2 key wrapped by the V1 key, and vice versa.
    expect(vector.account.upgradeToken!.wrapped_user_key_2.toString()).toMatch(/^2\./);
    expect(vector.account.upgradeToken!.wrapped_user_key_1.toString()).toMatch(/^7\./);
  });

  it(
    "reaches its V2 blob vault from a V1 master-password unlock",
    async () => {
      const method = vector.unlockMethods.find((m) => "masterPasswordUnlock" in m)!;
      const client = await unlockWithOrganizations(vector, method);

      // The user key the client ends up holding is the upgraded V2 key, which is the only key that
      // opens the blob vault below.
      expect((await client.crypto().get_user_encryption_key()).toString()).toBe(
        vector.rawCryptographicState.userKey,
      );
      expect(vector.rawCryptographicState.userKeyId).not.toBeNull();

      await validateVectorDirectly(vector, method);
      expect(vector.vault.ciphers.every((cipher) => cipher.blobEncrypted)).toBe(true);
    },
    UNLOCK_TIMEOUT,
  );
});
