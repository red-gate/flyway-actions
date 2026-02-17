import tseslint from 'typescript-eslint';
import importPlugin from 'eslint-plugin-import';
import vitestPlugin from '@vitest/eslint-plugin';

export default [
  { ignores: ['**/dist/**', '**/node_modules/**', '**/*.js', '!eslint.config.mjs'] },
  {
    files: ['**/*.ts'],
    plugins: {
      '@typescript-eslint': tseslint.plugin,
      import: importPlugin,
    },
    linterOptions: { reportUnusedDisableDirectives: 'error' },
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: { projectService: true },
      sourceType: 'module',
    },
    settings: {
      'import/extensions': ['.ts'],
    },
    rules: {
      // eslint rules
      'arrow-body-style': ['error', 'as-needed'],
      'arrow-parens': ['off', 'as-needed'],
      curly: 'warn',
      'eol-last': 'off',
      eqeqeq: ['warn', 'smart'],
      'linebreak-style': 'off',
      'max-len': 'off',
      'new-parens': 'off',
      'newline-per-chained-call': 'off',
      'no-cond-assign': 'warn',
      'no-console': ['warn', { allow: ['error'] }],
      'no-debugger': 'warn',
      'no-else-return': 'error',
      'no-empty-pattern': 'error',
      'no-extra-semi': 'off',
      'no-irregular-whitespace': 'off',
      'no-multiple-empty-lines': 'off',
      'no-restricted-exports': [
        'error',
        {
          restrictDefaultExports: {
            defaultFrom: true,
            direct: true,
            named: true,
            namedFrom: true,
            namespaceFrom: true,
          },
        },
      ],
      'no-restricted-syntax': [
        'error',
        {
          selector: 'FunctionDeclaration',
          message: 'Use const with an arrow function instead of function declarations.',
        },
        {
          selector: 'ImportDeclaration:not([importKind="type"])[source.value=vitest]',
          message: 'Utilities from Vitest are available as globals and should not be imported',
        },
        {
          selector: 'Literal[value=/\\bPlease\\b/i]',
          message: "Avoid using the word 'Please' in strings",
        },
      ],
      'no-trailing-spaces': 'off',
      'no-var': 'error',
      'object-shorthand': 'error',
      'prefer-arrow-callback': ['warn', { allowNamedFunctions: true }],
      'prefer-const': 'warn',
      'prefer-template': 'warn',
      'quote-props': 'off',
      'require-await': 'off',
      'space-before-function-paren': 'off',
      'spaced-comment': ['error', 'always'],
      'template-curly-spacing': ['error', 'never'],
      // @typescript-eslint rules
      '@typescript-eslint/await-thenable': 'error',
      '@typescript-eslint/consistent-type-assertions': ['warn', { assertionStyle: 'as' }],
      '@typescript-eslint/consistent-type-imports': [
        'error',
        { fixStyle: 'separate-type-imports', prefer: 'type-imports' },
      ],
      '@typescript-eslint/indent': 'off',
      '@typescript-eslint/member-delimiter-style': [
        'off',
        'error',
        {
          singleline: { delimiter: 'semi', requireLast: false },
          multiline: { delimiter: 'none', requireLast: true },
        },
      ],
      '@typescript-eslint/no-deprecated': 'error',
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          destructuredArrayIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrors: 'none',
          ignoreRestSiblings: true,
        },
      ],
      '@typescript-eslint/quotes': 'off',
      '@typescript-eslint/require-await': 'error',
      '@typescript-eslint/semi': ['off', null],
      '@typescript-eslint/space-within-parens': ['off', 'never'],
      '@typescript-eslint/type-annotation-spacing': 'off',
      // import rules
      'import/consistent-type-specifier-style': ['error', 'prefer-top-level'],
      'import/export': 'warn',
      'import/group-exports': 'error',
      'import/no-duplicates': ['warn', { 'prefer-inline': false }],
      'import/order': [
        'warn',
        {
          groups: ['type', 'builtin', 'external', 'parent', 'sibling', 'index'],
          named: true,
          alphabetize: { order: 'asc', orderImportKind: 'asc' },
        },
      ],
    },
  },
  {
    files: ['**/tests/**/*.test.ts'],
    plugins: { vitest: vitestPlugin },
    rules: {
      'no-console': 'off',
      'vitest/consistent-test-it': ['error', { fn: 'it' }],
      'vitest/no-commented-out-tests': 'error',
      'vitest/no-identical-title': 'error',
      'vitest/no-import-node-test': 'error',
      'vitest/no-restricted-vi-methods': [
        'error',
        { mock: 'vi.mock is hoisted which can cause hard-to-debug errors. Prefer vi.doMock' },
      ],
      'vitest/padding-around-all': 'error',
      'vitest/prefer-hooks-in-order': 'error',
      'vitest/prefer-hooks-on-top': 'error',
      'vitest/valid-describe-callback': 'error',
      'vitest/valid-expect': 'error',
      'vitest/valid-title': 'error',
    },
  }
];
