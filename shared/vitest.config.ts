import { defineConfig } from "vitest/config";

// noinspection JSUnusedGlobalSymbols
export default defineConfig({
  test: {
    globals: true,
    mockReset: true,
    environment: "node",
    include: ["tests/**/*.test.ts"],
  },
});
