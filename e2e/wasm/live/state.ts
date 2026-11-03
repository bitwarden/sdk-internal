// What live runs keep between runs, in `.live/` (gitignored): the secret test-account passwords
// derive from, and the ledger of accounts created and deleted.

import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

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

interface LedgerEntry {
  email: string;
  event: "created" | "deleted";
  at: string;
}

/** Records that an account was created or deleted. */
export function recordAccount(email: string, event: LedgerEntry["event"]): void {
  mkdirSync(STATE_DIR, { recursive: true });
  const entry: LedgerEntry = { email, event, at: new Date().toISOString() };
  appendFileSync(LEDGER_FILE, `${JSON.stringify(entry)}\n`);
}

/** Accounts created at least `ageMs` ago that no entry records as deleted. */
export function undeletedAccounts(ageMs: number): string[] {
  if (!existsSync(LEDGER_FILE)) {
    return [];
  }

  const created = new Map<string, number>();
  for (const line of readFileSync(LEDGER_FILE, "utf8").split("\n")) {
    if (line.trim() === "") {
      continue;
    }

    const entry = JSON.parse(line) as LedgerEntry;
    if (entry.event === "created") {
      created.set(entry.email, Date.parse(entry.at));
    } else {
      created.delete(entry.email);
    }
  }

  const cutoff = Date.now() - ageMs;
  return [...created].filter(([, at]) => at <= cutoff).map(([email]) => email);
}
