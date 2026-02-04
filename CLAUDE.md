# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository is for GitHub Actions that integrate Flyway (a database migration tool) with GitHub workflows. It is a Redgate project.

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
