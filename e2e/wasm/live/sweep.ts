// Deletes the test accounts a crashed live run left behind, before the next live run starts.
//
// Runs as Vitest's global setup in live mode. An account goes once it is an hour old and the ledger
// has no record of its deletion, so a run still in progress elsewhere on this machine keeps its own.
// One the server has no account for, with this secret's password, is recorded absent and not
// tried again.

import { TestAccounts } from "./accounts";
import { liveConfig } from "./config";
import { undeletedAccounts } from "./state";

const LEFT_BEHIND_AFTER_MS = 60 * 60 * 1000;

export default async function setup(): Promise<void> {
  const config = liveConfig();
  if (config === undefined) {
    return;
  }

  const leftBehind = undeletedAccounts(LEFT_BEHIND_AFTER_MS);
  if (leftBehind.length === 0) {
    return;
  }

  const accounts = new TestAccounts({ ...config, ledger: true });
  const outcomes = { deleted: 0, absent: 0, failed: 0 };
  for (const email of leftBehind) {
    try {
      outcomes[await accounts.deleteByEmail(email)] += 1;
    } catch {
      outcomes.failed += 1;
    }
  }

  console.log(
    `live sweep: deleted ${outcomes.deleted} account(s) a previous run left behind` +
      (outcomes.absent > 0 ? `; ${outcomes.absent} no longer existed` : "") +
      (outcomes.failed > 0
        ? `; ${outcomes.failed} could not be deleted and stay in the ledger`
        : ""),
  );
}
