# CLAUDE.md

## Project Overview

This repository is for GitHub Actions that integrate Flyway (a database migration tool) with GitHub workflows. It is a Redgate product.

## Structure

This is a GitHub Action with:
- `action.yml` in the root directory (standard GitHub Actions metadata)
- Source code in `src/` or `dist/`
- `package.json` for dependencies and scripts
- Use TypeScript for development
- Tests in `tests/` directory
- Use ViTest for testing
- CI/CD workflows in `.github/workflows/`
- Documentation in `README.md` files
- Linting with ESLint and Prettier

## Code Style Guidelines

### Comments and Documentation
- Write self-documenting code. Variable names, function names, and structure should make the code's intent clear.
- Avoid comments unless absolutely necessary for complex logic that cannot be clarified through refactoring.
- Do NOT use JSDoc comments (`/** ... */`). The code should be self-explanatory without documentation comments.

### Tests
- Use values that do not cause typo warnings

## Committing Changes

- Commit messages should be as terse as possible. No need for long descriptions or a commit signature.
- Before creating any commit, ALWAYS run formatting, linting, and tests for the affected project(s) only — not the entire monorepo.

Example workflow:
1. Make code changes
2. Run `yarn format` for affected project(s)
3. Run `yarn lint` for affected project(s)
4. Run `yarn test` for affected project(s)
5. Stage and commit the changes

## Pull Request Workflow

- PR descriptions should be terse. No long explanations or verbose checklists.
- When raising a PR, follow these steps to ensure the "check dist is up to date" build step passes:

1. Fetch latest changes: `git fetch`
2. Rebase on main: `git rebase origin/main`
3. Install dependencies: `yarn install`
4. Build the distribution: `yarn build`
5. Commit the changes to `dist/` if any files were updated
6. Push the branch and create the PR

This ensures the built distribution files in `dist/` are always up to date with the source code. There only ever needs to be one commit per PR that updates build distribution files, typically at the end.
