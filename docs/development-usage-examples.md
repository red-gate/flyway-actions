# Development Workflow Usage Examples

Workflows that support developers authoring schema changes — for example, generating migration scripts from schema model edits at pull-request time so reviewers see the SQL alongside the model changes.

## Generate migrations on a pull request

This is the canonical setup for the [`migrations/generate`](../migrations/generate) action. By default the action stages, commits, and pushes the generated files back to the branch the workflow ran on. Set `commit-migrations: false` to opt out. Authentication uses the credentials persisted by `actions/checkout`, so:

- the job needs `permissions: contents: write`
- `actions/checkout` must run first with its default `persist-credentials: true`
- on `pull_request` events, pass `ref: ${{ github.head_ref }}` to `actions/checkout` (as shown in the example below) so commits land on the PR branch rather than the detached merge commit
- if you need the push to re-trigger CI on the PR, check out with a PAT or app token (`GITHUB_TOKEN` pushes do not re-trigger workflows)
- pushes from forked PRs are not possible; this workflow is only useful for same-repo PRs

```yaml
name: Generate Flyway migrations

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  generate:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
      - uses: red-gate/setup-flyway@v3
        with:
          edition: enterprise
          i-agree-to-the-eula: true
          email: ${{ secrets.REDGATE_EMAIL }}
          token: ${{ secrets.REDGATE_TOKEN }}
      - uses: red-gate/flyway-actions/migrations/generate@v2
        with:
          build-environment: build
          build-user: ${{ secrets.DB_USER }}
          build-password: ${{ secrets.DB_PASSWORD }}
          working-directory: my-flyway-project
          migration-description: add_orders_table
```
