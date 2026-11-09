// Accounts a test seeds for itself, and destroys when it ends, on either backend.
//
// Nothing depends on a long-lived account: files can run in parallel without sharing one, and a run
// leaves nothing behind for the next to trip over.

import { randomBytes, randomUUID } from "node:crypto";

import { Seeder, type SeederSettings } from "./seeder";

/** A person on the environment under test. */
export interface TestAccount {
  email: string;
  password: string;
}

export interface AccountSettings {
  /** The server's seeder, which writes each account and destroys it. */
  seeder: SeederSettings;
  /** The domain test addresses use; `example.com` never delivers mail (RFC 2606). */
  emailDomain: string;
}

/**
 * Creates accounts through the server's seeder, under one play id per instance, and destroys the
 * play when the test ends. A play that is never destroyed, because the run crashed, is removed by
 * the server's own cleanup of old plays.
 */
export class TestAccounts {
  private readonly runTag = `${new Date().toISOString().slice(0, 10).replaceAll("-", "")}-${randomBytes(4).toString("hex")}`;

  private readonly seeder: Seeder;

  /** The play this instance seeds under, from its first account until it is destroyed. */
  private playId: string | undefined;

  private count = 0;

  constructor(private readonly config: AccountSettings) {
    this.seeder = new Seeder(config.seeder);
  }

  /**
   * Seeds a new account, answering the address it logs in with and its password.
   *
   * TODO: seed V2 accounts once the seeder can; until then every account is V1.
   */
  async create(): Promise<TestAccount> {
    this.playId ??= randomUUID();
    this.count += 1;

    const requested = `sdk-it-${this.runTag}-${this.count}@${this.config.emailDomain}`;
    const password = randomBytes(24).toString("base64url");
    const email = await this.seeder.seedUser(this.playId, requested, password);

    return { email, password };
  }

  /** Destroys every account this instance seeded. */
  async deleteAll(): Promise<void> {
    const playId = this.playId;
    if (playId === undefined) {
      return;
    }

    this.playId = undefined;
    await this.seeder.destroyPlay(playId);
  }
}
