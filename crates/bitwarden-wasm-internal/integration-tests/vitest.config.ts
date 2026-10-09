// Vitest runs only the performance harnesses (`npm run perf`); the integration suite stays on jest.
import { defineConfig } from "vitest/config";

export default defineConfig({
  // The SDK package's `module` field points at the bundler build; Node needs `main` (node/ target).
  resolve: { mainFields: ["main"] },
  test: {
    include: [],
    // Harnesses run one after another so they don't compete for CPU.
    fileParallelism: false,
    // The default reporter omits bench tables when stdout is not a TTY, e.g. in CI logs.
    reporters: ["verbose"],
    benchmark: { include: ["perf/**/*.perf.ts"] },
  },
});
