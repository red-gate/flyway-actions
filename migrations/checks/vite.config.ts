/* eslint-disable no-restricted-exports */
import { builtinModules, createRequire } from "node:module";
import checker from "vite-plugin-checker";
import { defineConfig } from "vitest/config";

const require = createRequire(import.meta.url);
const nodeBuiltins = builtinModules.flatMap((m) => [m, `node:${m}`]);

// noinspection JSUnusedGlobalSymbols
export default defineConfig({
  build: {
    lib: {
      entry: {
        index: "src/main.ts",
      },
      formats: ["es"],
      fileName: (_format, entryName) => `${entryName}.js`,
    },
    rollupOptions: { external: nodeBuiltins },
    target: "node24",
    minify: "esbuild",
    outDir: "dist",
    emptyOutDir: true,
  },
  resolve: {
    conditions: ["node"],
    // Rollup's CommonJS plugin can't resolve these transitive deps of @actions/artifact
    // through Yarn PnP, so we alias them explicitly to ensure they get bundled.
    alias: {
      "@protobuf-ts/runtime": require.resolve("@protobuf-ts/runtime"),
      "@protobuf-ts/runtime-rpc": require.resolve("@protobuf-ts/runtime-rpc"),
    },
  },
  plugins: [checker({ typescript: { root: "." } })],
  test: {
    globals: true,
    mockReset: true,
    environment: "node",
    include: ["tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "html", "lcov"],
      include: ["src/**/*.ts"],
      exclude: ["src/main.ts"],
    },
  },
});
