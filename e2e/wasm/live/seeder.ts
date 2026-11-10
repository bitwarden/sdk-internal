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

  /**
   * Uploads a user vector, unchanged: the scene stores its account and vault, already encrypted,
   * and ignores the plaintext the vector records for the tests' own assertions.
   */
  async seedUserVector(vector: UserVector): Promise<SeededVector> {
    const response = await this.request("POST", "/seed", {
      template: "TestVectorUserScene",
      arguments: vector,
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
