// Runs every `perf/*.perf.ts` harness, or those whose name contains the first CLI argument.
//
//   npm run perf             all harnesses
//   npm run perf -- unlock   unlock.perf.ts only

import { readdirSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const PERF_SUFFIX = ".perf.ts";

const dir = dirname(fileURLToPath(import.meta.url));
const filter = process.argv[2] ?? "";

const harnesses = readdirSync(dir)
  .filter((f) => f.endsWith(PERF_SUFFIX) && f.includes(filter))
  .sort();

if (harnesses.length === 0) {
  throw new Error(`no harness matches "${filter}"`);
}

for (const harness of harnesses) {
  const { run } = (await import(pathToFileURL(`${dir}/${harness}`).href)) as {
    run: () => Promise<void>;
  };
  await run();
}
