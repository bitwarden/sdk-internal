// Registering a fresh account on a live server, as a real client does it.
//
//   POST /accounts/register/send-verification-email ──▶ "Verify Your Email" ──▶ token
//                                                                                  │
//   registration().post_keys_for_user_password_registration(token) ◀──────────────┘
//
// The first request is plain `fetch`: the SDK has no method for it, and a real client sends it
// before it has an account. The second goes through the SDK, so the real server checks the
// register-finish request the SDK builds.

import type { ClientSettings } from "@bitwarden/sdk-internal";

import { makePasswordManagerClient, makeStateBridge } from "../tests/utils";

import type { LiveAccount } from "./config";
import { Mailbox, type Email } from "./mailbox";

/** The subject of the message that carries the registration link. */
const VERIFICATION_SUBJECT = "Verify Your Email";

/** The name the account registers under, so it is obvious where it came from. */
const ACCOUNT_NAME = "sdk-internal integration tests";

/**
 * Registers a new account with a master password, at a random address on the mail server.
 *
 * The account is V2 from the start, with the server's default KDF.
 */
export async function registerAccount(settings: ClientSettings): Promise<LiveAccount> {
  const mailbox = Mailbox.random();
  const email = mailbox.address;
  const password = `sdk-internal-${crypto.randomUUID()}`;

  // 1. Start the registration. A server with email verification turned off returns the token
  //    directly; otherwise it mails the registration link.
  const token =
    (await sendVerificationEmail(settings, email)) ??
    registrationToken(await mailbox.waitFor(VERIFICATION_SUBJECT), email);

  // 2. Finish it through the SDK. The client is unauthenticated and carries no account.
  await makePasswordManagerClient(makeStateBridge(), settings)
    .auth()
    .registration()
    .post_keys_for_user_password_registration({
      email,
      // Clients salt the master password with the email, trimmed and lowercased.
      salt: email,
      master_password: password,
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

  return { email, password };
}

/**
 * `POST /accounts/register/send-verification-email`.
 *
 * Returns the token when the server answers with it, and `null` when it mailed the token instead.
 */
async function sendVerificationEmail(
  settings: ClientSettings,
  email: string,
): Promise<string | null> {
  const url = `${settings.identityUrl}/accounts/register/send-verification-email`;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(settings.bitwardenClientVersion === undefined
        ? {}
        : { "Bitwarden-Client-Version": settings.bitwardenClientVersion }),
    },
    body: JSON.stringify({ email, name: ACCOUNT_NAME, receiveMarketingEmails: false }),
  });

  const body = await response.text();
  if (!response.ok) {
    throw new Error(`POST ${url} answered ${response.status}: ${body}`);
  }

  if (response.status === 204 || body === "") {
    return null;
  }

  // The token comes back as a JSON string or as plain text, depending on content negotiation.
  return body.startsWith('"') ? (JSON.parse(body) as string) : body;
}

/**
 * The token in the registration link of a "Verify Your Email" message.
 *
 * The link carries its parameters in the URL fragment:
 * `…/redirect-connector.html#finish-signup?token=…&email=…&fromEmail=true`.
 */
function registrationToken(message: Email, email: string): string {
  const link = message.text.match(/https?:\/\/\S+#finish-signup\?\S+/)?.[0];
  if (link === undefined) {
    throw new Error(`message ${message.id} has no registration link:\n${message.text}`);
  }

  const params = new URLSearchParams(new URL(link).hash.slice("#finish-signup?".length));
  const token = params.get("token");
  if (token === null || token === "") {
    throw new Error(`the registration link in message ${message.id} has no token: ${link}`);
  }
  if (params.get("email") !== email) {
    throw new Error(`the registration link in message ${message.id} is for another address`);
  }

  return token;
}
