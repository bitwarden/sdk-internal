import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    // `describe`/`it`/`expect` are available without an import in every test file. Typed via the
    // `vitest/globals` entry in tsconfig.json.
    globals: true,
    include: ["tests/**/*.test.ts"],
  },
});
