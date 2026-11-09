// The server's seeder API (`util/SeederApi`): test data written straight to the database, tagged
// with a play id, and destroyed by it. A test environment may run one; production never does.

/** Where the seeder is, and the basic-authentication pair it accepts. */
export interface SeederSettings {
  url: string;
  username: string;
  password: string;
}

/** The scene the seeder creates a standalone account with. */
const SINGLE_USER_SCENE = "SingleUserScene";

/** The query that reads back the email-verification link a server mailed. */
const EMAIL_VERIFICATION_QUERY = "UserEmailVerificationQuery";

interface SeedResponse {
  /**
   * The values the seeder replaced so seeded data cannot collide, keyed by the value asked for. A
   * seeder with mangling on stores an address with a prefix; one with it off leaves it out.
   */
  mangleMap?: Record<string, string | null>;
}

export class Seeder {
  constructor(private readonly settings: SeederSettings) {}

  /**
   * Seeds an account with a master password under `playId`, and answers the address it was stored
   * under, which is the one it logs in with.
   *
   * The seeder makes the account's keys itself. Its response also carries the account's decrypted
   * user key, which is never read: a test reaches the vault only by logging in, as a client does.
   */
  async seedUser(playId: string, email: string, password: string): Promise<string> {
    const response = await this.send("POST", "/seed", playId, {
      template: SINGLE_USER_SCENE,
      arguments: { email, password, emailVerified: true },
    });
    const { mangleMap } = (await response.json()) as SeedResponse;

    return mangleMap?.[email] ?? email;
  }

  /** Destroys everything seeded under `playId`. One the seeder has no record of is a no-op. */
  async destroyPlay(playId: string): Promise<void> {
    await this.send("DELETE", `/seed/${encodeURIComponent(playId)}`, playId);
  }

  /**
   * The email-verification link a registration for `email` was mailed, relative and with its
   * parameters in the fragment: `/redirect-connector.html#finish-signup?token=…&email=…`.
   */
  async emailVerificationLink(email: string, name: string): Promise<string> {
    const response = await this.send("POST", "/query", undefined, {
      template: EMAIL_VERIFICATION_QUERY,
      arguments: { email, name },
    });
    const { url } = (await response.json()) as { url: string };

    return url;
  }

  private async send(
    method: string,
    path: string,
    playId: string | undefined,
    body?: unknown,
  ): Promise<Response> {
    const { url, username, password } = this.settings;
    const response = await fetch(`${url}${path}`, {
      method,
      headers: {
        Authorization: `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`,
        ...(playId === undefined ? {} : { "X-Play-Id": playId }),
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) {
      throw new Error(`the seeder answered ${method} ${path} with ${response.status}`);
    }

    return response;
  }
}
