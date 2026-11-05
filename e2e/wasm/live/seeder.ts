// Seeding a real server with the test vectors the emulator loads, through the server's SeederApi
// (`bitwarden/server` `util/SeederApi`, scene `TestVectorUserScene`). Development servers only: the
// SeederApi refuses to run in production.

import { randomUUID } from "node:crypto";

import type { UserVector } from "../vectors/load";

/** Where the SeederApi is, and its basic-authentication account. */
export interface SeederConfig {
  url: string;
  username: string;
  password: string;
}

/** A vector seeded on the server: its account, and the ids its items were given there. */
export interface SeededVector {
  userId: string;
  email: string;
  /** Vector cipher id → seeded cipher id. */
  cipherIds: Record<string, string>;
  /** Vector folder id → seeded folder id. */
  folderIds: Record<string, string>;
}

/**
 * One play on the SeederApi: everything it seeds is removed again by {@link cleanup}.
 *
 * Each seeding gets fresh ids and a mangled email, so tests can seed the same vector at once.
 */
export class SeederClient {
  private readonly playId = `sdk-internal-${randomUUID()}`;

  constructor(private readonly config: SeederConfig) {}

  /** Seeds a user vector as it is: its account and vault, already encrypted. */
  async seedUserVector(vector: UserVector): Promise<SeededVector> {
    const response = await this.request("POST", "/seed", {
      template: "TestVectorUserScene",
      arguments: serverHalf(vector),
    });

    return ((await response.json()) as { result: SeededVector }).result;
  }

  /** Removes everything this play seeded. */
  async cleanup(): Promise<void> {
    await this.request("DELETE", `/seed/${this.playId}`);
  }

  private async request(method: string, path: string, body?: unknown): Promise<Response> {
    const credentials = Buffer.from(`${this.config.username}:${this.config.password}`).toString(
      "base64",
    );
    const response = await fetch(`${this.config.url}${path}`, {
      method,
      headers: {
        Authorization: `Basic ${credentials}`,
        "Content-Type": "application/json",
        "X-Play-Id": this.playId,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) {
      throw new Error(
        `seeder ${method} ${path} answered ${response.status}: ${await response.text()}`,
      );
    }

    return response;
  }
}

/**
 * The part of a vector a server holds: wrapped keys, public keys, the authentication hash and the
 * encrypted vault. The plaintext the vector records for its own assertions never leaves the test.
 */
function serverHalf(vector: UserVector): unknown {
  const { password: _password, ...account } = vector.account;
  const raw = vector.rawCryptographicState;

  return {
    name: vector.name,
    account,
    unlockMethods: vector.unlockMethods.flatMap((method) =>
      "masterPasswordUnlock" in method
        ? [
            {
              masterPasswordUnlock: {
                master_password_unlock: method.masterPasswordUnlock.master_password_unlock,
              },
            },
          ]
        : [],
    ),
    masterPasswordAuthenticationHash: vector.masterPasswordAuthenticationHash,
    rawCryptographicState: {
      publicKey: raw.publicKey,
      verifyingKey: raw.verifyingKey,
      userKeyId: raw.userKeyId,
    },
    vault: {
      ciphers: vector.vault.ciphers.map(({ id, encrypted }) => ({ id, encrypted })),
      folders: (vector.vault.folders ?? []).map(({ id, encrypted }) => ({ id, encrypted })),
    },
  };
}
