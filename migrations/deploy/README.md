# Flyway Migrations Deployment Action

A GitHub Action to deploy your Flyway migrations to a target database.

## Behavior under different editions

### Flyway Enterprise

When running under Flyway Enterprise the following steps will be run by default

#### Drift detection

Compares your target database against the expected state, ensuring that nothing has changed since your last deployment.
Note that this will only be able to flag up drift after your first deployment, once a snapshot of the database has been captured.
This operation is only available for databases with [advanced comparison capability support](https://documentation.red-gate.com/flyway/flyway-concepts/database-comparisons).
For more information, see [the associated Flyway documentation](https://documentation.red-gate.com/flyway/flyway-concepts/drift-analysis).

#### Deployment

Deploys your [Flyway migrations](https://documentation.red-gate.com/flyway/flyway-concepts/migrations) using the [migrate command](https://documentation.red-gate.com/flyway/reference/commands/migrate).

#### Stores a snapshot

Captures a snapshot after deployment and stores it in the Flyway snapshot history table, enabling drift checks the next time you deploy, as well as allowing for [ad hoc rollbacks](https://documentation.red-gate.com/flyway/deploying-database-changes-using-flyway/implementing-a-roll-back-strategy).
This operation is only available for databases with [advanced comparison capability support](https://documentation.red-gate.com/flyway/flyway-concepts/database-comparisons).

### Flyway Teams

Only the deployment will be performed

### Flyway Community

Only the deployment will be performed

## Prerequisites

This action requires Flyway to be installed. Use [`red-gate/setup-flyway@v3`](https://github.com/red-gate/setup-flyway) before this action:

```yaml
- uses: red-gate/setup-flyway@v3
  with:
    edition: enterprise
    i-agree-to-the-eula: true
    email: ${{ secrets.REDGATE_EMAIL }}
    token: ${{ secrets.REDGATE_TOKEN }}
- uses: red-gate/flyway-actions/migrations/deploy@v1
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
  - uses: red-gate/flyway-actions/migrations/deploy@v1
    with:
      target-environment: qa
      target-user: ${{ secrets.DB_USER }}
      target-password: ${{ secrets.DB_PASSWORD }}
      working-directory: my-flyway-project
```

### With Cherry-Pick (Teams/Enterprise)

```yaml
- uses: red-gate/setup-flyway@v3
  with:
    edition: enterprise
    i-agree-to-the-eula: true
    email: ${{ secrets.REDGATE_EMAIL }}
    token: ${{ secrets.REDGATE_TOKEN }}
- uses: red-gate/flyway-actions/migrations/deploy@v1
  with:
    target-environment: production
    target-user: ${{ secrets.DB_USER }}
    target-password: ${{ secrets.DB_PASSWORD }}
    cherry-pick: '2.0,2.1,3.0'
```

## Inputs

| Input                      | Description                                                    | Required                                 | Default |
|----------------------------|----------------------------------------------------------------|------------------------------------------|---------|
| `target-environment`       | Target database to deploy to                                   | Required if `target-url` not set         |         |
| `target-url`               | JDBC URL for the target database                               | Required if `target-environment` not set |         |
| `target-user`              | Database user                                                  | No                                       |         |
| `target-password`          | Database password                                              | No                                       |         |
| `target-schemas`           | Comma-separated list of schemas                                | No                                       |         |
| `target-migration-version` | Migrate up to this version                                     | No                                       |         |
| `cherry-pick`              | Comma-separated list of migration versions to apply            | No                                       |         |
| `skip-drift-check`         | Skip the drift check                                           | No                                       | false   |
| `working-directory`        | Working directory for Flyway                                   | No                                       |         |
| `extra-args`               | Additional Flyway CLI arguments (e.g. `-sqlMigrationPrefix=M`) | No                                       |         |

## Outputs

| Output               | Description                                   |
|----------------------|-----------------------------------------------|
| `exit-code`          | Flyway exit code                              |
| `drift-detected`     | Whether drift was detected (empty if skipped) |
| `migrations-applied` | Number of migrations applied                  |
| `schema-version`     | Schema version after deployment               |

### Using Outputs

```yaml
- uses: red-gate/flyway-actions/migrations/deploy@v1
  id: migrate
  with:
    target-environment: production

- run: echo "Applied ${{ steps.migrate.outputs.migrations-applied }} migrations"
- run: echo "Schema is now at version ${{ steps.migrate.outputs.schema-version }}"
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
