// The shared harness for `change_kdf`.
//
// A KDF change needs an unlocked account whose master-password unlock data is real, so the harness
// seeds an account into the model server, syncs it into local state and unlocks it — the same route
// a client takes. Tests get the server, the local state and the unlocked client together.

import type { CipherView, Kdf, PasswordManagerClient } from "@bitwarden/sdk-internal";

import { PASSWORD_ACCOUNT, PASSWORD_ACCOUNT_USER_KEY } from "../fixtures/accounts";
import type { Routes } from "../http-mock";
import { ApiServer, type SeedAccount } from "../model-server/api-server";
import { installServers, type InstalledServers } from "../model-server/install";
import { LocalState } from "../model-server/local-state";
import {
  expectedVaultOf,
  syncToLocalState,
  unlockMethodFor,
  type ExpectedVault,
} from "../model-server/validate";

/** Two KDF derivations per change — the old one to prove possession, the new one to re-wrap. */
export const CHANGE_KDF_TIMEOUT = 120_000;

export const CHANGE_KDF_ROUTE = "POST /accounts/kdf";

export const NEW_PBKDF2: Kdf = { pBKDF2: { iterations: 700_000 } };
export const NEW_ARGON2: Kdf = { argon2id: { iterations: 3, memory: 16, parallelism: 4 } };

/** The item the harness puts in the account's vault, so a validation has something to prove. */
const SEEDED_ITEM = {
  name: "Seeded Login",
  notes: "notes that must survive a kdf change",
  username: "someone@example.com",
  password: "the-item-password",
} as const;

export interface ChangeKdfHarness {
  api: ApiServer;
  servers: InstalledServers;
  local: LocalState;
  client: PasswordManagerClient;
  account: SeedAccount;
  email: string;
  /** The plaintext the account's vault must still decrypt to, keyed by item id. */
  expected: ExpectedVault;
  assertClean(): void;
}

/**
 * Seeds `account`, installs the API model, syncs the account into local state and unlocks it.
 *
 * `extraRoutes` overrides endpoints on the API origin, which is how the failure cases make the KDF
 * change be rejected without disturbing the rest of the model.
 */
/**
 * Whether the harness puts an item in the account's vault.
 *
 * `"seeded"` for any case that validates the account afterwards — a validator with nothing to
 * decrypt reports success for an account it never opened. `"empty"` for cases that only assert a
 * refusal, and for accounts whose key material cannot encrypt one.
 */
export type VaultSeeding = "seeded" | "empty";

export async function setupChangeKdf(
  options: { account?: SeedAccount; extraRoutes?: Routes; vault?: VaultSeeding } = {},
): Promise<ChangeKdfHarness> {
  const account = options.account ?? PASSWORD_ACCOUNT;
  const api = new ApiServer();
  api.seedUser(account);
  const servers = installServers({ api, extraRoutes: options.extraRoutes });

  const email = account.account.email;
  const local = new LocalState();
  await syncToLocalState(api, email, local);
  const client = await local.unlock(unlockMethodFor(api, email));

  // Created through the real path, so the ciphertext is the SDK's own rather than a fixture's.
  const created =
    (options.vault ?? "seeded") === "empty"
      ? undefined
      : await client
          .vault()
          .ciphers()
          .create({
            organizationId: undefined,
            collectionIds: [],
            folderId: undefined,
            name: SEEDED_ITEM.name,
            notes: SEEDED_ITEM.notes,
            favorite: false,
            reprompt: 0,
            type: { login: loginView() },
            fields: [],
          });
  await syncToLocalState(api, email, local);

  return {
    api,
    servers,
    local,
    client,
    account,
    email,
    expected: expectedVaultOf({
      ...account,
      vault:
        created === undefined
          ? {}
          : {
              ciphers: [
                {
                  id: String(created.id),
                  encrypted: encryptedOf(api, created),
                  decrypted: created,
                },
              ],
            },
    }),
    assertClean() {
      expect(servers.unmatched.map((request) => request.route)).toEqual([]);
      // The account's password, user key and private key are watched by the server on every
      // request, so no individual test has to remember to look at a body.
      expect(api.secretLeaks()).toEqual([]);
      servers.restore();
    },
  };
}

function loginView() {
  return {
    username: SEEDED_ITEM.username,
    password: SEEDED_ITEM.password,
    passwordRevisionDate: undefined,
    uris: undefined,
    totp: undefined,
    autofillOnPageLoad: undefined,
    fido2Credentials: undefined,
  };
}

/** The ciphertext the server stored for `view`. */
function encryptedOf(api: ApiServer, view: CipherView) {
  const stored = api.db.ciphers.get(String(view.id));
  if (stored === undefined) {
    throw new Error(`the create did not reach the server: no cipher ${String(view.id)}`);
  }
  return stored;
}

/**
 * Asserts the recorded user key is the one the account actually unwraps to.
 *
 * The server can only watch for a secret it was told about. If the fixture's recorded user key ever
 * drifts from its key material, the leak check would keep passing while covering nothing — so it is
 * re-derived once here rather than trusted.
 */
export async function expectRecordedUserKeyIsLive(client: PasswordManagerClient): Promise<void> {
  expect(await client.crypto().get_user_encryption_key()).toBe(PASSWORD_ACCOUNT_USER_KEY);
}
