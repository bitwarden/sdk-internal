// Accounts a test file creates for itself and deletes when it ends, on either backend.
//
// Nothing depends on a long-lived account: files can run in parallel without sharing one, and a run
// leaves nothing behind for the next to trip over.

import { createHmac, pbkdf2Sync, randomBytes } from "node:crypto";

import { PureCrypto, type ClientSettings, type LoginRequest } from "@bitwarden/sdk-internal";

import { makePasswordManagerClient, makeStateBridge } from "../tests/utils";

import { recordAccount } from "./state";

/** A person on the environment under test. */
export interface TestAccount {
  email: string;
  password: string;
}

/** The server's seeder API, which reads back the email-verification token a server mailed. */
export interface SeederSettings {
  url: string;
  username: string;
  password: string;
}

export interface AccountSettings {
  settings: ClientSettings;
  loginRequest: LoginRequest;
  /** The secret passwords derive from. */
  secret: string;
  /** The domain test addresses use; `example.com` never delivers mail (RFC 2606). */
  emailDomain: string;
  seeder?: SeederSettings;
  /** Whether to keep a ledger, so a later run can delete what a crashed one left. */
  ledger: boolean;
}

/** The name registration records. */
const NAME = "SDK Integration Tests";

/**
 * Thrown when the environment gives no way to read the email-verification token, so no account can
 * be created. A test that needs an account skips on it rather than failing.
 */
export class RegistrationUnavailableError extends Error {}

/** Creates accounts through registration, and deletes them through the server's API. */
export class TestAccounts {
  private readonly created: TestAccount[] = [];

  private readonly runTag = `${new Date().toISOString().slice(0, 10).replaceAll("-", "")}-${randomBytes(4).toString("hex")}`;

  constructor(private readonly config: AccountSettings) {}

  /**
   * Registers a new account, as a client does: the server is told the address, the token that
   * proves it is read back, and the SDK finishes the registration with keys it makes on the device.
   */
  async create(): Promise<TestAccount> {
    const email = `sdk-it-${this.runTag}-${this.created.length + 1}@${this.config.emailDomain}`;
    const account = { email, password: passwordFor(this.config.secret, email) };

    const token = await this.emailVerificationToken(email);
    if (this.config.ledger) {
      recordAccount(email, "created");
    }

    await makePasswordManagerClient(makeStateBridge(), this.config.settings)
      .auth()
      .registration()
      .post_keys_for_user_password_registration({
        email,
        salt: email,
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

    this.created.push(account);
    return account;
  }

  /**
   * Deletes every account this instance created, newest first. Tries them all, then throws if any
   * failed, so a teardown problem is reported rather than hidden.
   */
  async deleteAll(): Promise<void> {
    const failures: string[] = [];
    for (const account of this.created.splice(0).reverse()) {
      try {
        await this.delete(account);
      } catch (error) {
        failures.push(`${account.email}: ${String(error)}`);
      }
    }

    if (failures.length > 0) {
      throw new Error(
        `could not delete ${failures.length} test account(s): ${failures.join("; ")}`,
      );
    }
  }

  /** Deletes an account by its address alone, as the sweep does for a crashed run's. */
  async deleteByEmail(email: string): Promise<void> {
    await this.delete({ email, password: passwordFor(this.config.secret, email) });
  }

  /**
   * Signs in, then deletes the account, proving possession of its master password.
   *
   * The SDK has no method to delete an account yet, so the request goes to the server directly, with
   * the authentication hash derived from the SDK's KDF.
   */
  private async delete(account: TestAccount): Promise<void> {
    const login = makePasswordManagerClient(makeStateBridge(), this.config.settings).auth().login();
    const prelogin = await login.get_password_prelogin(account.email);
    const response = await login.login_via_password({
      loginRequest: this.config.loginRequest,
      email: account.email,
      password: account.password,
      preloginResponse: prelogin,
    });

    const deleted = await fetch(`${this.config.settings.apiUrl}/accounts`, {
      method: "DELETE",
      headers: {
        Authorization: `Bearer ${response.Authenticated.accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        masterPasswordHash: masterPasswordHash(account.password, prelogin.salt, prelogin.kdf),
      }),
    });
    if (!deleted.ok) {
      throw new Error(`deleting the account answered ${deleted.status}: ${await deleted.text()}`);
    }

    if (this.config.ledger) {
      recordAccount(account.email, "deleted");
    }
  }

  /**
   * Starts a registration and reads back the token that proves the address.
   *
   * A server with email verification off answers with the token. One with it on mails the token
   * and answers 204, and only the seeder can read it back.
   */
  private async emailVerificationToken(email: string): Promise<string> {
    const { identityUrl, bitwardenClientVersion } = this.config.settings;
    const response = await fetch(`${identityUrl}/accounts/register/send-verification-email`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        ...(bitwardenClientVersion ? { "Bitwarden-Client-Version": bitwardenClientVersion } : {}),
      },
      body: JSON.stringify({ email, name: NAME, receiveMarketingEmails: false }),
    });

    if (response.status === 200) {
      return parseToken(await response.text());
    }
    if (response.status !== 204) {
      throw new Error(
        `starting registration answered ${response.status}: ${await response.text()}`,
      );
    }

    const seeder = this.config.seeder;
    if (seeder === undefined) {
      throw new RegistrationUnavailableError(
        "the server mails the email-verification token, and no seeder is configured to read it back",
      );
    }

    const queried = await fetch(`${seeder.url}/query`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Basic ${Buffer.from(`${seeder.username}:${seeder.password}`).toString("base64")}`,
      },
      body: JSON.stringify({
        template: "UserEmailVerificationQuery",
        arguments: { email, name: NAME },
      }),
    });
    if (!queried.ok) {
      throw new Error(`the seeder's verification query answered ${queried.status}`);
    }

    // The link is the one the email carries, relative and with its parameters in the fragment:
    // `/redirect-connector.html#finish-signup?token=…&email=…`.
    const { url } = (await queried.json()) as { url: string };
    const token = /[?&]token=([^&]+)/.exec(url)?.[1];
    if (token === undefined) {
      throw new Error("the seeder's verification link carries no token");
    }

    return decodeURIComponent(token);
  }
}

/**
 * A test account's master password: an HMAC of its address under the run's secret. Deterministic,
 * so the account can be deleted later from its address alone, and unguessable without the secret.
 */
function passwordFor(secret: string, email: string): string {
  const mac = createHmac("sha256", secret).update(email.toLowerCase()).digest("base64url");
  return `Sdk!${mac.slice(0, 28)}`;
}

/**
 * The master password's authentication hash, as the server stores it: the master key from the
 * SDK's KDF, then one round of PBKDF2 over the password.
 */
function masterPasswordHash(
  password: string,
  salt: string,
  kdf: Parameters<typeof PureCrypto.derive_kdf_material>[2],
): string {
  const encoder = new TextEncoder();
  const masterKey = PureCrypto.derive_kdf_material(
    encoder.encode(password),
    encoder.encode(salt),
    kdf,
  );

  return pbkdf2Sync(
    Buffer.from(masterKey),
    Buffer.from(password, "utf8"),
    1,
    32,
    "sha256",
  ).toString("base64");
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
