import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import importPlugin from 'eslint-plugin-import';

export default tseslint.config(
  eslint.configs.recommended,
  tseslint.configs.recommended,
  { ignores: ['**/dist/**', '**/node_modules/**', '**/*.js', '!eslint.config.js'] },
  {
    plugins: {
      import: importPlugin,
    },
    rules: {
      'func-style': ['error', 'expression', { allowArrowFunctions: true }],
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'import/group-exports': 'error',
    },
  }
);
