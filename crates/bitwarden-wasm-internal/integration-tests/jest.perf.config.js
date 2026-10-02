import base from "./jest.config.js";

// Performance harnesses live in `perf/` and are excluded from the regular suite.
/** @type {import('jest').Config} */
export default {
  ...base,
  testMatch: ["**/perf/**/*.perf.ts"],
  testTimeout: 30 * 60 * 1000,
};
