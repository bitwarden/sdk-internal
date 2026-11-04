import type { CipherView, PasswordManagerClient } from "@bitwarden/sdk-internal";

import { LoginMethod, type ClientEmulator } from "../../client-emulator/client-emulator";
import type { TargetAccount } from "../../test-harness";

/** The item {@link ensureVaultNotEmpty} adds, named so it is obvious where it came from. */
const PLACEHOLDER_NAME = "sdk-internal integration tests";

/**
 * Whether the rotation issues a V2 upgrade token.
 *
 * Only a V1 to V2 rotation produces one, and it is what lets a session already unlocked on the old
 * key re-initialize onto the new one instead of unlocking again.
 */
export type UpgradeTokenAction = "CreateIfNeeded" | "Skip";

/** Rotates with the account's password, either upgrading to V2 or carrying V2 forward. */
export async function rotateByPassword(
  sdk: PasswordManagerClient,
  password: string,
  upgradeTokenAction: UpgradeTokenAction,
): Promise<void> {
  await sdk.user_crypto_management().rotate_user_keys({
    key_rotation_method: { Password: { password } },
    trusted_emergency_access_public_keys: [],
    trusted_organization_public_keys: [],
    upgrade_token_action: upgradeTokenAction,
  });
}

/** A client logged in, synced and unlocked. */
export async function session(account: TargetAccount): Promise<ClientEmulator> {
  const client = account.newClient();
  await client.login(account.email, LoginMethod.Password, account.password);
  await client.unlock(account.password);

  return client;
}

/** Same as {@link session}, for many clients at once. Sequential: logins are not the test. */
export async function sessions(account: TargetAccount, count: number): Promise<ClientEmulator[]> {
  const clients: ClientEmulator[] = [];
  for (let i = 0; i < count; i++) {
    clients.push(await session(account));
  }

  return clients;
}

/** Gives the account something to rotate; a rotation over an empty vault proves nothing. */
export async function ensureVaultNotEmpty(client: ClientEmulator): Promise<void> {
  const sdk = client.getPasswordManagerClient();
  if ((await sdk.vault().ciphers().get_all()).successes.length > 0) {
    return;
  }

  await createLogin(client, PLACEHOLDER_NAME, "created by the rotation tests");
  await client.sync();
}

export async function createLogin(
  client: ClientEmulator,
  name: string,
  notes: string,
): Promise<CipherView> {
  return await client
    .getPasswordManagerClient()
    .vault()
    .ciphers()
    .create({
      organizationId: undefined,
      collectionIds: [],
      folderId: undefined,
      name,
      notes,
      favorite: false,
      reprompt: 0,
      type: {
        login: {
          username: "integration-tests@example.com",
          password: "a password the rotation has to carry across",
          passwordRevisionDate: undefined,
          uris: undefined,
          totp: undefined,
          autofillOnPageLoad: undefined,
          fido2Credentials: undefined,
        },
      },
      fields: [],
    });
}
