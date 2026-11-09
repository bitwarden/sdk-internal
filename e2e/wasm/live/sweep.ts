// Deletes the test accounts and seeder plays a crashed live run left behind, before the next live
// run starts.
//
// Runs as Vitest's global setup in live mode. An account or play goes once it is an hour old and the
// ledger has no record of its deletion, so a run still in progress elsewhere on this machine keeps
// its own. An account the server has no record of, with this secret's password, is recorded absent
// and not tried again.

import { TestAccounts } from "./accounts";
import { liveConfig } from "./config";
import { Seeder } from "./seeder";
import { ledgerServer, recordPlay, undeletedAccounts, undeletedPlays } from "./state";

const LEFT_BEHIND_AFTER_MS = 60 * 60 * 1000;

export default async function setup(): Promise<void> {
  const config = liveConfig();
  if (config === undefined) {
    return;
  }

  // Registered accounts are swept whatever this run's source, as are plays whenever a seeder is
  // configured: an earlier run may have used the other source.
  const leftBehind = undeletedAccounts(ledgerServer(config.settings), LEFT_BEHIND_AFTER_MS);
  if (leftBehind.length > 0) {
    const accounts = new TestAccounts({ ...config, accountSource: "register", ledger: true });
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

  const seeder = config.seeder;
  const plays = seeder === undefined ? [] : undeletedPlays(seeder.url, LEFT_BEHIND_AFTER_MS);
  if (seeder !== undefined && plays.length > 0) {
    let failed = 0;
    for (const play of plays) {
      try {
        await new Seeder(seeder).destroyPlay(play);
        recordPlay(seeder.url, play, "deleted");
      } catch {
        failed += 1;
      }
    }

    console.log(
      `live sweep: destroyed ${plays.length - failed} seeder play(s) a previous run left behind` +
        (failed > 0 ? `; ${failed} could not be destroyed and stay in the ledger` : ""),
    );
  }
}
