# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository is for GitHub Actions that integrate Flyway (a database migration tool) with GitHub workflows. It is a Redgate project.

## Git Safety Rules

**CRITICAL: NEVER PUSH TO MAIN**

- NEVER run `git push` when on the main branch
- NEVER run `git push origin main` under any circumstances
- ALWAYS work on a feature branch
- ALWAYS create a pull request for code review before merging to main
- If you accidentally switch to main, immediately switch back to a feature branch

This rule is absolute and must be followed without exception.

## Expected Structure

This is a mono repo for many GitHub Actions related to Redgate products. Each action will have its own directory under the product name it supports e.g. `flyway/`.

When implemented, this will likely be a GitHub Action with:
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

## Committing Changes

Commit messages should be as terse as possible. No need for long descriptions or a commit signature.
Before creating any commit, ALWAYS run `yarn format` to ensure code formatting is consistent across the codebase. This should be done for every commit without exception.

Example workflow:
1. Make code changes
2. Run `yarn format` to apply Prettier formatting
3. Run `yarn lint` to verify ESLint rules
4. Run `yarn test` to verify tests pass
5. Stage and commit the changes

## Pull Request Workflow

When raising a PR, follow these steps to ensure the "check dist is up to date" build step passes:

1. Fetch latest changes: `git fetch`
2. Rebase on main: `git rebase origin/main`
3. Install dependencies: `yarn install`
4. Build the distribution: `yarn build`
5. Commit the changes to `dist/` if any files were updated
6. Push the branch and create the PR

This ensures the built distribution files in `dist/` are always up to date with the source code.
