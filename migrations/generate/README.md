# Flyway Migrations Generate Action

A GitHub Action to generate Flyway migrations by comparing your schema model against a [build environment](https://documentation.red-gate.com/flyway/flyway-concepts/environments/shadow-and-build-environments).

## Behavior

Runs [`flyway diff`](https://documentation.red-gate.com/flyway/reference/commands/diff) followed by [`flyway generate`](https://documentation.red-gate.com/flyway/reference/commands/generate) to produce migration scripts capturing the differences between your source (default `schemaModel`) and the build database. The migration types (e.g. versioned, undo, repeatable) default to whatever is configured in your `flyway.toml`.

This action requires Flyway Enterprise edition.

## Prerequisites

This action requires Flyway to be installed. Use [`red-gate/setup-flyway@v3`](https://github.com/red-gate/setup-flyway) before this action:

```yaml
- uses: red-gate/setup-flyway@v3
  with:
    edition: enterprise
    i-agree-to-the-eula: true
    email: ${{ secrets.REDGATE_EMAIL }}
    token: ${{ secrets.REDGATE_TOKEN }}
- uses: red-gate/flyway-actions/migrations/generate@v2
  with:
    build-url: jdbc:postgresql://localhost/build
```

## Usage

By default the action stages, commits, and pushes the generated files back to the branch the workflow ran on. Set `commit-migrations: false` to opt out. Authentication uses the credentials persisted by `actions/checkout`, so:

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
          description: add_orders_table
```

## Inputs

| Input               | Description                                                                                       | Required | Default                                                 |
|---------------------|---------------------------------------------------------------------------------------------------|----------|---------------------------------------------------------|
| `source`            | Source for the diff                                                                               | No       | `schemaModel`                                           |
| `types`             | Comma-separated migration types to generate (e.g. `versioned,undo`). Defaults to reading the TOML | No       |                                                         |
| `description`       | Description used in the generated migration filename                                              | No       |                                                         |
| `build-environment` | Build database environment used as the diff target                                                | No       |                                                         |
| `build-url`         | JDBC URL for the build database                                                                   | No       |                                                         |
| `build-user`        | Database user for the build database                                                              | No       |                                                         |
| `build-password`    | Database password for the build database                                                          | No       |                                                         |
| `build-schemas`     | Comma-separated list of schemas for the build database                                            | No       |                                                         |
| `working-directory` | Working directory for Flyway                                                                      | No       |                                                         |
| `extra-args`        | Additional Flyway CLI arguments                                                                   | No       |                                                         |
| `commit-migrations` | Commit and push the generated migrations                                                          | No       | `true`                                                  |
| `commit-message`    | Commit message used when `commit-migrations` is enabled                                           | No       | `Generate Flyway migrations`                            |
| `commit-user-name`  | Git `user.name` used when `commit-migrations` is enabled                                          | No       | `github-actions[bot]`                                   |
| `commit-user-email` | Git `user.email` used when `commit-migrations` is enabled                                         | No       | `41898282+github-actions[bot]@users.noreply.github.com` |
| `commit-branch`     | Branch to push the commit to. Defaults to the current branch (`GITHUB_REF_NAME`)                  | No       |                                                         |

If you do not pass any `build-*` inputs, the build environment is taken from your `flyway.toml`.

## Outputs

| Output         | Description                                                       |
|----------------|-------------------------------------------------------------------|
| `exit-code`    | Flyway exit code                                                  |
| `script-paths` | JSON array of paths to the generated migration files              |
| `committed`    | `true` if the generated migrations were committed and pushed      |

The summary written to `$GITHUB_STEP_SUMMARY` lists each generated script, a table of the changes it captures (object name, object type, difference type), and any per-script warnings emitted by Flyway.

### Using Outputs

```yaml
- id: generate
  uses: red-gate/flyway-actions/migrations/generate@v2
  with:
    build-environment: build

- run: echo "Generated ${{ fromJson(steps.generate.outputs.script-paths)[0] }}"
```

## Secrets

Store database credentials and license tokens in [GitHub Actions secrets](../../README.md#best-practices-for-secrets) rather than hardcoding them in workflow files.

## License

MIT
