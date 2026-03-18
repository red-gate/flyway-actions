# Flyway Migrations Undo Action

A GitHub Action to undo your Flyway migrations on a target database, rolling back to a previous database schema state by using [undo migrations](https://documentation.red-gate.com/flyway/flyway-concepts/migrations/undo-migrations).

## Behavior under different editions

### Flyway Enterprise

When running under Flyway Enterprise the following steps will be run by default

#### Drift detection

Compares your target database against the expected state, ensuring that nothing has changed since your last deployment.
This operation is only available for databases with [advanced comparison capability support](https://documentation.red-gate.com/flyway/flyway-concepts/database-comparisons).
For more information, see [the associated Flyway documentation](https://documentation.red-gate.com/flyway/flyway-concepts/drift-analysis).

#### Undo

Reverts your [Flyway migrations](https://documentation.red-gate.com/flyway/flyway-concepts/migrations) using the [undo command](https://documentation.red-gate.com/flyway/reference/commands/undo).

#### Stores a snapshot

Captures a snapshot after undo and stores it in the Flyway snapshot history table, enabling drift checks the next time you deploy or undo.
This operation is only available for databases with [advanced comparison capability support](https://documentation.red-gate.com/flyway/flyway-concepts/database-comparisons).

### Flyway Teams

Only the undo will be performed

### Flyway Community

The undo command is not available in Flyway Community edition. Upgrade to Teams or Enterprise to use this action.

## Prerequisites

This action requires Flyway to be installed. Use [`red-gate/setup-flyway@v3`](https://github.com/red-gate/setup-flyway) before this action:

```yaml
- uses: red-gate/setup-flyway@v3
  with:
    edition: enterprise
    i-agree-to-the-eula: true
    email: ${{ secrets.REDGATE_EMAIL }}
    token: ${{ secrets.REDGATE_TOKEN }}
- uses: red-gate/flyway-actions/migrations/undo@v1
  with:
    target-environment: production
```

## Usage

### Basic Example

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: red-gate/setup-flyway@v3
    with:
      edition: enterprise
      i-agree-to-the-eula: true
      email: ${{ secrets.REDGATE_EMAIL }}
      token: ${{ secrets.REDGATE_TOKEN }}
  - uses: red-gate/flyway-actions/migrations/undo@v1
    with:
      target-environment: qa
      target-user: ${{ secrets.DB_USER }}
      target-password: ${{ secrets.DB_PASSWORD }}
      working-directory: my-flyway-project
```

### Undo to a Specific Version

```yaml
- uses: red-gate/setup-flyway@v3
  with:
    edition: enterprise
    i-agree-to-the-eula: true
    email: ${{ secrets.REDGATE_EMAIL }}
    token: ${{ secrets.REDGATE_TOKEN }}
- uses: red-gate/flyway-actions/migrations/undo@v1
  with:
    target-environment: production
    target-user: ${{ secrets.DB_USER }}
    target-password: ${{ secrets.DB_PASSWORD }}
    target-migration-version: '2.0'
```

### With Cherry-Pick (Teams/Enterprise)

```yaml
- uses: red-gate/setup-flyway@v3
  with:
    edition: enterprise
    i-agree-to-the-eula: true
    email: ${{ secrets.REDGATE_EMAIL }}
    token: ${{ secrets.REDGATE_TOKEN }}
- uses: red-gate/flyway-actions/migrations/undo@v1
  with:
    target-environment: production
    target-user: ${{ secrets.DB_USER }}
    target-password: ${{ secrets.DB_PASSWORD }}
    cherry-pick: '3.0,2.1,2.0'
```

## Inputs

| Input                      | Description                                                    | Required                                 | Default |
|----------------------------|----------------------------------------------------------------|------------------------------------------|---------|
| `target-environment`       | Target database to undo migrations on                          | Required if `target-url` not set         |         |
| `target-url`               | JDBC URL for the target database                               | Required if `target-environment` not set |         |
| `target-user`              | Database user                                                  | No                                       |         |
| `target-password`          | Database password                                              | No                                       |         |
| `target-schemas`           | Comma-separated list of schemas                                | No                                       |         |
| `target-migration-version` | Undo migrations down to this version                           | No                                       |         |
| `cherry-pick`              | Comma-separated list of migration versions to undo             | No                                       |         |
| `skip-drift-check`         | Skip the drift check                                           | No                                       | false   |
| `working-directory`        | Working directory for Flyway                                   | No                                       |         |
| `extra-args`               | Additional Flyway CLI arguments (e.g. `-sqlMigrationPrefix=M`) | No                                       |         |

### Undo Report Upload

When running under Flyway Enterprise and drift is detected, the action uploads the undo report as a workflow artifact.

| Input                        | Description                                           | Required | Default              |
|------------------------------|-------------------------------------------------------|----------|----------------------|
| `undo-report-name`           | Name for the undo report artifact                     | No       | `flyway-undo-report` |
| `undo-report-retention-days` | Number of days to retain the undo report artifact     | No       | `7`                  |
| `skip-undo-report-upload`    | Skip uploading the undo report as a workflow artifact | No       | `false`              |

If the 'undo' action runs more than once in the same workflow (e.g. against multiple target databases), use a unique `undo-report-name` for each run to avoid artifact name conflicts:

```yaml
strategy:
  matrix:
    target: [staging, production]
steps:
  - uses: red-gate/flyway-actions/migrations/undo@v1
    with:
      target-environment: ${{ matrix.target }}
      undo-report-name: flyway-undo-report-${{ matrix.target }}
```

### Drift Resolution Scripts Upload

When drift is detected, Flyway generates SQL scripts that can be used to resolve the drift. The action uploads these as a workflow artifact.

| Input                                     | Description                                                    | Required | Default                           |
|-------------------------------------------|----------------------------------------------------------------|----------|-----------------------------------|
| `drift-resolution-scripts-name`           | Name for the drift resolution scripts artifact                 | No       | `flyway-drift-resolution-scripts` |
| `drift-resolution-scripts-retention-days` | Number of days to retain the drift resolution scripts artifact | No       | `7`                               |
| `skip-drift-resolution-scripts-upload`    | Skip uploading drift resolution scripts as a workflow artifact | No       | `false`                           |

As with undo reports, use a unique `drift-resolution-scripts-name` when running against multiple targets:

```yaml
strategy:
  matrix:
    target: [staging, production]
steps:
  - uses: red-gate/flyway-actions/migrations/undo@v1
    with:
      target-environment: ${{ matrix.target }}
      drift-resolution-scripts-name: flyway-drift-resolution-${{ matrix.target }}
```

## Outputs

| Output              | Description                                   |
|---------------------|-----------------------------------------------|
| `exit-code`         | Flyway exit code                              |
| `drift-detected`    | Whether drift was detected (empty if skipped) |
| `migrations-undone` | Number of migrations undone                   |
| `schema-version`    | Schema version after undo                     |

### Using Outputs

```yaml
- uses: red-gate/flyway-actions/migrations/undo@v1
  id: undo
  with:
    target-environment: production

- run: echo "Undone ${{ steps.undo.outputs.migrations-undone }} migrations"
- run: echo "Schema is now at version ${{ steps.undo.outputs.schema-version }}"
```

## Secrets

Store database credentials and license tokens in [GitHub Actions secrets](../../README.md#best-practices-for-secrets) rather than hardcoding them in workflow files. Use environment-scoped secrets for production targets.

## Supported Databases

This action supports all databases supported by Flyway:

- PostgreSQL
- MySQL / MariaDB
- SQL Server
- Oracle
- SQLite
- DB2
- Snowflake
- BigQuery
- [And more](https://documentation.red-gate.com/flyway/getting-started-with-flyway/system-requirements/supported-databases-and-versions)

However, the drift check and snapshot generation are only supported for databases with [advanced comparison capability support](https://documentation.red-gate.com/flyway/flyway-concepts/database-comparisons).

## License

MIT
