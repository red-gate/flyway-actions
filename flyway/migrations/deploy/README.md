# Flyway Migrations Deployment Action

A GitHub Action to deploy your Flyway migrations to a target database.

## Prerequisites

This action requires Flyway to be installed. Use [`red-gate/setup-flyway@v1`](https://github.com/red-gate/setup-flyway) before this action:

```yaml
- uses: red-gate/setup-flyway@v1
- uses: red-gate/flyway-github-actions/flyway/migrations/deploy@v1
  with:
    environment: production
```

## Usage

### Basic Example

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: red-gate/setup-flyway@v1
  - uses: red-gate/flyway-github-actions/flyway/migrations/deploy@v1
    with:
      environment: qa
      url: jdbc:postgresql://localhost:5432/mydb
      user: ${{ secrets.DB_USER }}
      password: ${{ secrets.DB_PASSWORD }}
      working-directory: sql/migrations
```

### With Cherry-Pick (Teams/Enterprise)

```yaml
- uses: red-gate/setup-flyway@v1
  with:
    license-key: ${{ secrets.FLYWAY_LICENSE_KEY }}
- uses: red-gate/flyway-github-actions/flyway/migrations/deploy@v1
  with:
    environment: production
    url: ${{ secrets.DB_URL }}
    user: ${{ secrets.DB_USER }}
    password: ${{ secrets.DB_PASSWORD }}
    cherry-pick: '2.0,2.1,3.0'
```

## Inputs

| Input | Description | Required |
|-------|-------------|----------|
| `environment` | Flyway TOML environment name | No |
| `url` | JDBC URL for the database connection | No |
| `user` | Database user | No |
| `password` | Database password | No |
| `target` | Migrate up to this version | No |
| `cherry-pick` | Comma-separated list of migration versions to apply | No |
| `working-directory` | Working directory for Flyway execution | No |
| `extra-args` | Additional arguments to pass to Flyway | No |

## Outputs

| Output | Description |
|--------|-------------|
| `exit-code` | Flyway command exit code |
| `drift-detected` | Whether drift was detected (empty if skipped) |
| `migrations-applied` | Number of migrations applied |
| `schema-version` | Schema version after migration |

### Using Outputs

```yaml
- uses: red-gate/flyway-github-actions/flyway/migrations/deploy@v1
  id: migrate
  with:
    environment: production
    url: ${{ secrets.DB_URL }}

- run: echo "Applied ${{ steps.migrate.outputs.migrations-applied }} migrations"
- run: echo "Schema is now at version ${{ steps.migrate.outputs.schema-version }}"
```

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
- And many more

## License

MIT
