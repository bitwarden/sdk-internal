// Vitest runs the integration suite (`npm test`), the live-server suite (`npm run test:live`) and
// the performance harnesses (`npm run perf`).
import { defineConfig } from "vitest/config";

export default defineConfig(({ mode }) => ({
  // The SDK package's `module` field points at the bundler build; Node needs `main` (node/ target).
  resolve: { mainFields: ["main"] },
  test: {
    // Live suites run against a real server when `BW_LIVE_SERVER_URL` is set, and otherwise against
    // the emulator or not at all. A default run loads them too; `--mode live` loads only them.
    include: mode === "live" ? ["tests/**/*.live.test.ts"] : ["tests/**/*.test.ts"],
    // Tests use `describe`/`it`/`expect` without importing them.
    globals: true,
    // Harnesses run one after another so they don't compete for CPU, and live suites one after
    // another so they don't race on the same account.
    fileParallelism: mode !== "benchmark" && mode !== "live" && !process.env.BW_LIVE_SERVER_URL,
    // The default reporter omits bench tables when stdout is not a TTY, e.g. in CI logs.
    reporters: ["verbose"],
    benchmark: { include: ["perf/**/*.perf.ts"] },
  },
}));
