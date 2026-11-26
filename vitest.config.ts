import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    // Integration and e2e tests talk to MinIO and spawn the server; unit tests finish far below this.
    testTimeout: 30_000,
    hookTimeout: 120_000,
    restoreMocks: true,
  },
});
