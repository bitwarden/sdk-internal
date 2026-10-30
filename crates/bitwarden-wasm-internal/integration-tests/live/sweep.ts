// Deletes the test accounts a crashed live run left behind, before the next live run starts.
//
// Runs as Vitest's global setup in live mode. An account goes once it is an hour old and the ledger
// has no record of its deletion, so a run still in progress elsewhere on this machine keeps its own.

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
  let failed = 0;
  for (const email of leftBehind) {
    try {
      await accounts.deleteByEmail(email);
    } catch {
      failed += 1;
    }
  }

  console.log(
    `live sweep: deleted ${leftBehind.length - failed} account(s) a previous run left behind` +
      (failed > 0 ? `; ${failed} could not be deleted and stay in the ledger` : ""),
  );
}
