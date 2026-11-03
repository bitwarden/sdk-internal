// Vitest runs the integration suite (`npm test`) and the performance harnesses (`npm run perf`).
import { defineConfig } from "vitest/config";

export default defineConfig(({ mode }) => ({
  // The SDK package's `module` field points at the bundler build; Node needs `main` (node/ target).
  resolve: { mainFields: ["main"] },
  test: {
    include: ["tests/**/*.test.ts"],
    // Tests use `describe`/`it`/`expect` without importing them.
    globals: true,
    // Harnesses run one after another so they don't compete for CPU.
    fileParallelism: mode !== "benchmark",
    // The default reporter omits bench tables when stdout is not a TTY, e.g. in CI logs.
    reporters: ["verbose"],
    benchmark: { include: ["perf/**/*.perf.ts"] },
  },
}));
