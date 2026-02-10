# Flyway Migrate Action

A GitHub Action to run Flyway migrate command for database migrations.

## Prerequisites

This action requires Flyway to be installed. Use [`red-gate/setup-flyway@v1`](https://github.com/red-gate/setup-flyway) before this action:

```yaml
- uses: red-gate/setup-flyway@v1
- uses: red-gate/flyway-github-actions/flyway/migrations/deploy@v1
  with:
    url: jdbc:postgresql://localhost:5432/mydb
```

## Usage

### Basic Example

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: red-gate/setup-flyway@v1
  - uses: red-gate/flyway-github-actions/flyway/migrations/deploy@v1
    with:
      url: jdbc:postgresql://localhost:5432/mydb
      user: ${{ secrets.DB_USER }}
      password: ${{ secrets.DB_PASSWORD }}
      locations: filesystem:sql/migrations
```

### With Baseline on Migrate

```yaml
- uses: red-gate/flyway-github-actions/flyway/migrations/deploy@v1
  with:
    url: ${{ secrets.DB_URL }}
    user: ${{ secrets.DB_USER }}
    password: ${{ secrets.DB_PASSWORD }}
    baseline-on-migrate: 'true'
    baseline-version: '1.0'
```

### With Placeholders

```yaml
- uses: red-gate/flyway-github-actions/flyway/migrations/deploy@v1
  with:
    url: ${{ secrets.DB_URL }}
    user: ${{ secrets.DB_USER }}
    password: ${{ secrets.DB_PASSWORD }}
    placeholders: 'environment=production,tableName=users'
```

### With Cherry-Pick (Teams/Enterprise)

```yaml
- uses: red-gate/setup-flyway@v1
  with:
    license-key: ${{ secrets.FLYWAY_LICENSE_KEY }}
- uses: red-gate/flyway-github-actions/flyway/migrations/deploy@v1
  with:
    url: ${{ secrets.DB_URL }}
    user: ${{ secrets.DB_USER }}
    password: ${{ secrets.DB_PASSWORD }}
    cherry-pick: '2.0,2.1,3.0'
```

### Using Config Files

```yaml
- uses: red-gate/flyway-github-actions/flyway/migrations/deploy@v1
  with:
    url: ${{ secrets.DB_URL }}
    config-files: 'flyway.conf,flyway-prod.conf'
```

### Using Environment Variables

Flyway also reads configuration from environment variables. Any `FLYWAY_*` variable will be picked up:

```yaml
- uses: red-gate/flyway-github-actions/flyway/migrations/deploy@v1
  env:
    FLYWAY_URL: ${{ secrets.DB_URL }}
    FLYWAY_USER: ${{ secrets.DB_USER }}
    FLYWAY_PASSWORD: ${{ secrets.DB_PASSWORD }}
    FLYWAY_LOCATIONS: 'filesystem:sql'
  with:
    url: ${{ secrets.DB_URL }}  # url is still required as action input
```

## Inputs

### Connection

| Input | Description | Required |
|-------|-------------|----------|
| `url` | JDBC URL for the database connection | Yes |
| `user` | Database user | No |
| `password` | Database password | No |
| `driver` | Fully qualified JDBC driver class name | No |
| `connect-retries` | Max retries when connecting | No |
| `connect-retries-interval` | Seconds between retries | No |
| `init-sql` | SQL to run after connecting | No |

### Migration Locations

| Input | Description | Required |
|-------|-------------|----------|
| `locations` | Comma-separated migration locations | No |
| `config-files` | Comma-separated config file paths | No |
| `working-directory` | Working directory for Flyway | No |

### Schema Management

| Input | Description | Required |
|-------|-------------|----------|
| `schemas` | Comma-separated schemas managed by Flyway | No |
| `default-schema` | Default schema | No |
| `table` | Flyway schema history table name | No |
| `tablespace` | Tablespace for history table | No |
| `target` | Target version for migrations | No |

### Baseline

| Input | Description | Required |
|-------|-------------|----------|
| `baseline-on-migrate` | Auto-baseline on non-empty schema | No |
| `baseline-version` | Version for baseline | No |
| `baseline-description` | Description for baseline | No |

### Behavior

| Input | Description | Required |
|-------|-------------|----------|
| `out-of-order` | Allow out-of-order migrations | No |
| `validate-on-migrate` | Validate during migrate | No |
| `validate-migration-naming` | Validate migration naming | No |
| `mixed` | Allow mixed transactional statements | No |
| `group` | Group pending migrations in transaction | No |
| `installed-by` | Username for schema history | No |
| `skip-executing-migrations` | Skip execution, update history only | No |

### Teams/Enterprise Features

| Input | Description | Required |
|-------|-------------|----------|
| `cherry-pick` | Comma-separated migrations to apply | No |
| `dry-run-output` | Output file for dry run SQL | No |
| `batch` | Batch SQL statements | No |
| `stream` | Stream SQL statements | No |
| `error-overrides` | Error handling rules | No |
| `fail-on-missing-target` | Fail if target version missing | No |

### Placeholders

| Input | Description | Required |
|-------|-------------|----------|
| `placeholders` | Key=value pairs, comma-separated | No |
| `placeholder-replacement` | Enable placeholder replacement | No |
| `placeholder-prefix` | Placeholder prefix (default: `${`) | No |
| `placeholder-suffix` | Placeholder suffix (default: `}`) | No |

### Advanced

| Input | Description | Required |
|-------|-------------|----------|
| `encoding` | SQL file encoding | No |
| `callbacks` | Callback class names | No |
| `loggers` | Logger configuration | No |
| `jar-dirs` | Directories with JDBC drivers | No |
| `extra-args` | Additional Flyway arguments | No |

See [action.yml](./action.yml) for the complete list of inputs.

## Outputs

| Output | Description |
|--------|-------------|
| `exit-code` | Flyway command exit code |
| `flyway-version` | Version of Flyway used |
| `migrations-applied` | Number of migrations applied |
| `schema-version` | Schema version after migration |

### Using Outputs

```yaml
- uses: red-gate/flyway-github-actions/flyway/migrations/deploy@v1
  id: migrate
  with:
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
