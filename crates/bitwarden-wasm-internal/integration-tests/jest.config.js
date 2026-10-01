/** @type {import('jest').Config} */
export default {
  preset: "ts-jest/presets/default-esm",
  testEnvironment: "node",
  extensionsToTreatAsEsm: [".ts"],
  testMatch: ["**/*.test.ts"],
  // Live suites talk to a real server over the network. They self-skip without their environment
  // variables, but a default run should not load them at all; `npm run test:live` overrides this.
  testPathIgnorePatterns: ["/node_modules/", "\\.live\\.test\\.ts$"],
  moduleNameMapper: {
    "^(\\.{1,2}/.*)\\.js$": "$1",
  },
  transform: {
    "^.+\\.ts$": [
      "ts-jest",
      {
        useESM: true,
      },
    ],
  },
};
