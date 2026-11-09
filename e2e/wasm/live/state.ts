// What live runs keep between runs, in `.live/` (gitignored): the secret test-account passwords
// derive from, and the ledger of accounts and seeder plays created and deleted.

import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type { ClientSettings } from "@bitwarden/sdk-internal";

const SECRET = "BW_LIVE_SECRET";
const STATE_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../.live");
const SECRET_FILE = join(STATE_DIR, "secret");
const LEDGER_FILE = join(STATE_DIR, "ledger.jsonl");

/**
 * The secret test-account passwords are derived from: `BW_LIVE_SECRET`, or a random one generated
 * once per machine. Never printed.
 *
 * Deriving rather than storing passwords is what lets a later run delete an account a crashed run
 * left behind: the ledger holds only addresses.
 */
export function liveSecret(): string {
  const configured = process.env[SECRET];
  if (configured !== undefined && configured !== "") {
    return configured;
  }

  mkdirSync(STATE_DIR, { recursive: true });
  if (!existsSync(SECRET_FILE)) {
    try {
      writeFileSync(SECRET_FILE, randomBytes(32).toString("base64"), { mode: 0o600, flag: "wx" });
    } catch {
      // Another process created it first.
    }
  }

  return readFileSync(SECRET_FILE, "utf8").trim();
}

/**
 * One line of the ledger: a registered account, by its address, or a seeder play, by its id.
 */
interface LedgerEntry {
  /**
   * The server the account or play is on: the identity URL for an account, where it registered, or
   * the seeder's URL for a play. Neither means anything on another server, which would only find no
   * such account or play there.
   */
  server: string;
  email?: string;
  play?: string;
  /**
   * `absent` means the server rejected the account's credentials, so there is nothing left to
   * delete: its registration failed, or the secret its password derives from has changed since.
   * A play is never absent: destroying one the seeder has no record of succeeds.
   */
  event: "created" | "deleted" | "absent";
  at: string;
}

/** The server a ledger entry names: the identity service's URL, where accounts are registered. */
export function ledgerServer(settings: ClientSettings): string {
  if (settings.identityUrl === undefined) {
    throw new Error("a ledger needs the identity URL of the server its accounts are on");
  }

  return settings.identityUrl;
}

/** Records that a registered account on `server` was created, deleted or found absent. */
export function recordAccount(server: string, email: string, event: LedgerEntry["event"]): void {
  record({ server, email, event, at: new Date().toISOString() });
}

/** Records that a play on the seeder at `server` was created or destroyed. */
export function recordPlay(server: string, play: string, event: "created" | "deleted"): void {
  record({ server, play, event, at: new Date().toISOString() });
}

/**
 * Registered accounts on `server` created at least `ageMs` ago that no later entry records as
 * deleted or absent. Other servers' entries are left for a run against those servers.
 */
export function undeletedAccounts(server: string, ageMs: number): string[] {
  return undeleted(server, ageMs, (entry) => entry.email);
}

/** Plays on the seeder at `server` created at least `ageMs` ago and not since destroyed. */
export function undeletedPlays(server: string, ageMs: number): string[] {
  return undeleted(server, ageMs, (entry) => entry.play);
}

function record(entry: LedgerEntry): void {
  mkdirSync(STATE_DIR, { recursive: true });
  appendFileSync(LEDGER_FILE, `${JSON.stringify(entry)}\n`);
}

function undeleted(
  server: string,
  ageMs: number,
  keyOf: (entry: LedgerEntry) => string | undefined,
): string[] {
  if (!existsSync(LEDGER_FILE)) {
    return [];
  }

  const created = new Map<string, number>();
  for (const line of readFileSync(LEDGER_FILE, "utf8").split("\n")) {
    if (line.trim() === "") {
      continue;
    }

    const entry = JSON.parse(line) as LedgerEntry;
    const key = keyOf(entry);
    if (entry.server !== server || key === undefined) {
      continue;
    }

    if (entry.event === "created") {
      created.set(key, Date.parse(entry.at));
    } else {
      created.delete(key);
    }
  }

  const cutoff = Date.now() - ageMs;
  return [...created].filter(([, at]) => at <= cutoff).map(([key]) => key);
}
