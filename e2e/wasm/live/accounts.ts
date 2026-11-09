// Accounts a test file creates for itself and deletes when it ends, on either backend.
//
// Nothing depends on a long-lived account: files can run in parallel without sharing one, and a run
// leaves nothing behind for the next to trip over.

import { createHmac, randomBytes, randomUUID } from "node:crypto";

import {
  isPasswordLoginError,
  type ClientSettings,
  type LoginRequest,
} from "@bitwarden/sdk-internal";

import {
  makePasswordManagerClient,
  makeStateBridge,
  masterPasswordAuthenticationHash,
} from "../tests/utils";

import { Seeder, type SeederSettings } from "./seeder";
import { ledgerServer, recordAccount, recordPlay } from "./state";

/** A person on the environment under test. */
export interface TestAccount {
  email: string;
  password: string;
}

/**
 * Where test accounts come from: the server's seeder, or registration as a client registers. See
 * {@link TestAccounts}.
 */
export type AccountSource = "seeder" | "register";

export interface AccountSettings {
  settings: ClientSettings;
  loginRequest: LoginRequest;
  /** The secret passwords derive from. */
  secret: string;
  /** The domain test addresses use; `example.com` never delivers mail (RFC 2606). */
  emailDomain: string;
  accountSource: AccountSource;
  /**
   * The server's seeder. Seeder accounts need it; registration needs it only on a server that mails
   * the email-verification token, to read the token back.
   */
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

/**
 * Creates accounts, and deletes them when the test ends, by the configured {@link AccountSource}:
 *
 * - `seeder`: the server's seeder writes each account under the test's play id, and destroys the
 *   play when the test ends. The way to organizations and existing vault data too.
 * - `register`: each account registers as a client does, so registration and the SDK's key making
 *   are exercised as well, and is deleted through the server's API. The way that works where no
 *   seeder is deployed, production included.
 *
 * A test calls {@link create} either way.
 */
export class TestAccounts {
  private readonly created: TestAccount[] = [];

  private readonly runTag = `${new Date().toISOString().slice(0, 10).replaceAll("-", "")}-${randomBytes(4).toString("hex")}`;

  /** The play this instance seeds under, from its first seeded account until it is destroyed. */
  private playId: string | undefined;

  constructor(private readonly config: AccountSettings) {
    if (config.accountSource === "seeder" && config.seeder === undefined) {
      throw new Error("seeder accounts need the seeder's settings");
    }
  }

  /** Creates a new account, by the configured source, that logs in with the password it carries. */
  async create(): Promise<TestAccount> {
    const requested = `sdk-it-${this.runTag}-${this.created.length + 1}@${this.config.emailDomain}`;
    const password = passwordFor(this.config.secret, requested);

    const email =
      this.config.accountSource === "seeder"
        ? await this.seed(requested, password)
        : await this.register(requested, password);

    const account = { email, password };
    this.created.push(account);
    return account;
  }

  /**
   * Seeds an account under this instance's play id, answering the address it logs in with.
   *
   * The play is recorded before its first account is seeded, and left in place if seeding fails,
   * for the same reason as a registered account: the seeder may have written the account first.
   */
  private async seed(email: string, password: string): Promise<string> {
    if (this.playId === undefined) {
      this.playId = randomUUID();
      if (this.config.ledger) {
        recordPlay(this.seeder().url, this.playId, "created");
      }
    }

    return new Seeder(this.seeder()).seedUser(this.playId, email, password);
  }

  /**
   * Registers a new account, as a client does: the server is told the address, the token that
   * proves it is read back, and the SDK finishes the registration with keys it makes on the device.
   */
  private async register(email: string, password: string): Promise<string> {
    const token = await this.emailVerificationToken(email);
    // Recorded before registering, and left in place if registering fails: the server may have
    // created the account before the failure. The sweep deletes it if so, and records it absent if
    // not.
    if (this.config.ledger) {
      recordAccount(ledgerServer(this.config.settings), email, "created");
    }

    await makePasswordManagerClient(makeStateBridge(), this.config.settings)
      .auth()
      .registration()
      .post_keys_for_user_password_registration({
        email,
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

    return email;
  }

  /**
   * Deletes every account this instance created.
   *
   * Seeded accounts go together, with their play. Registered ones go one by one, newest first: all
   * are tried, then this throws if any failed, so a teardown problem is reported rather than hidden.
   */
  async deleteAll(): Promise<void> {
    if (this.config.accountSource === "seeder") {
      await this.destroyPlay();
      return;
    }

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

  /**
   * Destroys this instance's play, and with it every account seeded under it. A play that fails to
   * go stays in the ledger as created, for the sweep.
   */
  private async destroyPlay(): Promise<void> {
    const playId = this.playId;
    if (playId === undefined) {
      return;
    }

    this.created.splice(0);
    this.playId = undefined;
    await new Seeder(this.seeder()).destroyPlay(playId);
    if (this.config.ledger) {
      recordPlay(this.seeder().url, playId, "deleted");
    }
  }

  private seeder(): SeederSettings {
    if (this.config.seeder === undefined) {
      throw new Error("no seeder is configured");
    }

    return this.config.seeder;
  }

  /**
   * Deletes a registered account by its address alone, as the sweep does for a crashed run's.
   *
   * Answers `absent`, and records it, when the server rejects the account's credentials: then there
   * is no account this secret can delete, and retrying on every later run would only fail again.
   * Any other failure throws, so the account is tried again next run.
   */
  async deleteByEmail(email: string): Promise<"deleted" | "absent"> {
    try {
      await this.delete({ email, password: passwordFor(this.config.secret, email) });
      return "deleted";
    } catch (error) {
      if (!isPasswordLoginError(error) || error.variant !== "InvalidUsernameOrPassword") {
        throw error;
      }

      if (this.config.ledger) {
        recordAccount(ledgerServer(this.config.settings), email, "absent");
      }
      return "absent";
    }
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

    if (this.config.ledger) {
      recordAccount(ledgerServer(this.config.settings), account.email, "deleted");
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

    const url = await new Seeder(seeder).emailVerificationLink(email, NAME);
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
