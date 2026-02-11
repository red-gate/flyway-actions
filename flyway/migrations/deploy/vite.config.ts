import {defineConfig} from 'vitest/config';
import {builtinModules} from 'node:module';
import checker from 'vite-plugin-checker';

const nodeBuiltins = builtinModules.flatMap(m => [m, `node:${m}`]);

export default defineConfig({
  build: {
    lib: {
      entry: {
        index: 'src/main.ts',
      },
      formats: ['es'],
      fileName: (_format, entryName) => `${entryName}.js`,
    },
    rollupOptions: { external: nodeBuiltins },
    target: 'node24',
    minify: 'esbuild',
    outDir: 'dist',
    emptyOutDir: true,
  },
  plugins: [checker({typescript: {root: '.'}})],
  test: {
    globals: true,
    mockReset: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: ['src/main.ts'],
    },
  },
});
