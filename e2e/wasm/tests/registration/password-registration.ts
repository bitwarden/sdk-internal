// Registering an account with a master password as a client does, and deleting it, for the tests
// of registration itself. Other tests get their accounts from `harness.accounts`, which seeds them.

import {
  isPasswordLoginError,
  type ClientSettings,
  type LoginRequest,
} from "@bitwarden/sdk-internal";

import { Seeder, type SeederSettings } from "../../live/seeder";
import {
  makePasswordManagerClient,
  makeStateBridge,
  masterPasswordAuthenticationHash,
} from "../utils";

/** The name registration records. */
const NAME = "SDK Integration Tests";

/** An account registered with a master password. */
export interface RegisteredAccount {
  email: string;
  password: string;
}

/**
 * Registers an account as a client does: the server is told the address, the token that proves it
 * is read back, and the SDK finishes the registration with keys it makes on the device.
 *
 * A server that mails the token needs `seeder` to read it back.
 */
export async function registerWithPassword(
  settings: ClientSettings,
  account: RegisteredAccount,
  seeder?: SeederSettings,
): Promise<void> {
  const token = await emailVerificationToken(settings, account.email, seeder);

  await makePasswordManagerClient(makeStateBridge(), settings)
    .auth()
    .registration()
    .post_keys_for_user_password_registration({
      email: account.email,
      salt: account.email,
      master_password: account.password,
      master_password_hint: undefined,
      email_verification_token: token,
      sales_assisted_token: undefined,
      organization_user_id: undefined,
      org_invite_token: undefined,
      org_sponsored_free_family_plan_token: undefined,
      accept_emergency_access_invite_token: undefined,
      accept_emergency_access_id: undefined,
      provider_invite_token: undefined,
      provider_user_id: undefined,
      open_org_invite: undefined,
    });
}

/**
 * Signs in, then deletes the account, proving possession of its master password. Answers `absent`
 * when the server has no such account.
 *
 * The SDK has no method to delete an account yet, so the request goes to the server directly, with
 * the authentication hash derived from the SDK's KDF.
 */
export async function deleteAccount(
  settings: ClientSettings,
  loginRequest: LoginRequest,
  account: RegisteredAccount,
): Promise<"deleted" | "absent"> {
  const login = makePasswordManagerClient(makeStateBridge(), settings).auth().login();
  const prelogin = await login.get_password_prelogin(account.email);

  let accessToken: string;
  try {
    const response = await login.login_via_password({
      loginRequest,
      email: account.email,
      password: account.password,
      preloginResponse: prelogin,
    });
    accessToken = response.Authenticated.accessToken;
  } catch (error) {
    if (isPasswordLoginError(error) && error.variant === "InvalidUsernameOrPassword") {
      return "absent";
    }
    throw error;
  }

  const deleted = await fetch(`${settings.apiUrl}/accounts`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      masterPasswordHash: masterPasswordAuthenticationHash(
        account.password,
        prelogin.salt,
        prelogin.kdf,
      ),
    }),
  });
  if (!deleted.ok) {
    throw new Error(`deleting the account answered ${deleted.status}: ${await deleted.text()}`);
  }

  return "deleted";
}

/**
 * Starts a registration and reads back the token that proves the address.
 *
 * A server with email verification off answers with the token. One with it on mails the token and
 * answers 204, and only the seeder can read it back.
 */
async function emailVerificationToken(
  settings: ClientSettings,
  email: string,
  seeder: SeederSettings | undefined,
): Promise<string> {
  const response = await fetch(
    `${settings.identityUrl}/accounts/register/send-verification-email`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        ...(settings.bitwardenClientVersion
          ? { "Bitwarden-Client-Version": settings.bitwardenClientVersion }
          : {}),
      },
      body: JSON.stringify({ email, name: NAME, receiveMarketingEmails: false }),
    },
  );

  if (response.status === 200) {
    return parseToken(await response.text());
  }
  if (response.status !== 204) {
    throw new Error(`starting registration answered ${response.status}: ${await response.text()}`);
  }
  if (seeder === undefined) {
    throw new Error("the server mailed the email-verification token, and no seeder can read it");
  }

  const url = await new Seeder(seeder).emailVerificationLink(email, NAME);
  const token = /[?&]token=([^&]+)/.exec(url)?.[1];
  if (token === undefined) {
    throw new Error("the seeder's verification link carries no token");
  }

  return decodeURIComponent(token);
}

/** The token, whether the server sent it as JSON or as plain text. */
function parseToken(body: string): string {
  try {
    const parsed: unknown = JSON.parse(body);
    if (typeof parsed === "string") {
      return parsed;
    }
  } catch {
    // Plain text.
  }

  return body;
}
