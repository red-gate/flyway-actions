# Flyway State Prepare Action

A GitHub Action to generate a Flyway state-based deployment script by comparing your schema model against a target database.

## Behavior under different editions

### Flyway Enterprise

When running under Flyway Enterprise the following steps will be run by default

#### Drift detection

Compares your target database against the expected state, ensuring that nothing has changed since your last deployment.
Note that this will only be able to flag up drift after your first deployment, once a snapshot of the database has been captured.
This operation is only available for databases with [advanced comparison capability support](https://documentation.red-gate.com/flyway/flyway-concepts/database-comparisons).
For more information, see [the associated Flyway documentation](https://documentation.red-gate.com/flyway/flyway-concepts/drift-analysis).

#### Prepare

Generates a deployment script by comparing your schema model against the target database using the [prepare](https://documentation.red-gate.com/flyway/reference/commands/prepare) command.

### Flyway Teams / Community

The [prepare](https://documentation.red-gate.com/flyway/reference/commands/prepare) command requires Flyway Enterprise. This action is not supported on Teams or Community editions.

## Prerequisites

This action requires Flyway to be installed. Use [`red-gate/setup-flyway@v3`](https://github.com/red-gate/setup-flyway) before this action:

```yaml
- uses: red-gate/setup-flyway@v3
  with:
    edition: enterprise
    i-agree-to-the-eula: true
    email: ${{ secrets.REDGATE_EMAIL }}
    token: ${{ secrets.REDGATE_TOKEN }}
- uses: red-gate/flyway-actions/state/prepare@v1
  with:
    target-url: jdbc:postgresql://localhost/mydb
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
  - uses: red-gate/flyway-actions/state/prepare@v1
    with:
      target-environment: qa
      target-user: ${{ secrets.DB_USER }}
      target-password: ${{ secrets.DB_PASSWORD }}
      working-directory: my-flyway-project
```

### Without Undo Script Generation

```yaml
- uses: red-gate/flyway-actions/state/prepare@v1
  with:
    target-environment: production
    target-user: ${{ secrets.DB_USER }}
    target-password: ${{ secrets.DB_PASSWORD }}
    generate-undo: false
```

## Inputs

| Input                | Description                                      | Required                                 | Default   |
|----------------------|--------------------------------------------------|------------------------------------------|-----------|
| `target-environment` | Target database environment                      | Required if `target-url` not set         | `default` |
| `target-url`         | JDBC URL for the target database                 | Required if `target-environment` not set |           |
| `target-user`        | Database user                                    | No                                       |           |
| `target-password`    | Database password                                | No                                       |           |
| `target-schemas`     | Comma-separated list of schemas                  | No                                       |           |
| `generate-undo`      | Generate undo script alongside deploy script     | No                                       | `true`    |
| `fail-on-drift`      | Fail when drift is detected                      | No                                       | `true`    |
| `skip-drift-check`   | Skip the drift check                             | No                                       | `false`   |
| `working-directory`  | Working directory for Flyway                     | No                                       |           |
| `extra-args`         | Additional Flyway CLI arguments                  | No                                       |           |

### Drift Report Upload

When running under Flyway Enterprise and drift is detected, the action uploads the drift report as a workflow artifact.

| Input                         | Description                                            | Required | Default               |
|-------------------------------|--------------------------------------------------------|----------|-----------------------|
| `drift-report-name`           | Name for the drift report artifact                     | No       | `flyway-drift-report` |
| `drift-report-retention-days` | Number of days to retain the drift report artifact     | No       | `7`                   |
| `skip-drift-report-upload`    | Skip uploading the drift report as a workflow artifact | No       | `false`               |

If the prepare action runs more than once in the same workflow (e.g. against multiple target databases), use a unique `drift-report-name` for each run to avoid artifact name conflicts:

```yaml
strategy:
  matrix:
    target: [staging, production]
steps:
  - uses: red-gate/flyway-actions/state/prepare@v1
    with:
      target-environment: ${{ matrix.target }}
      drift-report-name: flyway-drift-report-${{ matrix.target }}
```

### Drift Resolution Scripts Upload

When drift is detected, Flyway generates SQL scripts that can be used to resolve the drift. The action uploads these as a workflow artifact.

| Input                                     | Description                                                    | Required | Default                           |
|-------------------------------------------|----------------------------------------------------------------|----------|-----------------------------------|
| `drift-resolution-scripts-name`           | Name for the drift resolution scripts artifact                 | No       | `flyway-drift-resolution-scripts` |
| `drift-resolution-scripts-retention-days` | Number of days to retain the drift resolution scripts artifact | No       | `7`                               |
| `skip-drift-resolution-scripts-upload`    | Skip uploading drift resolution scripts as a workflow artifact | No       | `false`                           |

As with drift reports, use a unique `drift-resolution-scripts-name` when running against multiple targets:

```yaml
strategy:
  matrix:
    target: [staging, production]
steps:
  - uses: red-gate/flyway-actions/state/prepare@v1
    with:
      target-environment: ${{ matrix.target }}
      drift-resolution-scripts-name: flyway-drift-resolution-${{ matrix.target }}
```

## Outputs

| Output             | Description                                   |
|--------------------|-----------------------------------------------|
| `exit-code`        | Flyway exit code                              |
| `drift-detected`   | Whether drift was detected (empty if skipped) |
| `script-path`      | Path to the generated deployment script       |
| `undo-script-path` | Path to the generated undo script             |

### Using Outputs

```yaml
- uses: red-gate/flyway-actions/state/prepare@v1
  id: prepare
  with:
    target-environment: production

- run: echo "Script path: ${{ steps.prepare.outputs.script-path }}"
```

## Secrets

Store database credentials and license tokens in [GitHub Actions secrets](../../README.md#best-practices-for-secrets) rather than hardcoding them in workflow files. Use environment-scoped secrets for production targets.

## Supported Databases

This action supports all databases supported by Flyway's state-based deployment:

- SQL Server
- PostgreSQL
- MySQL
- Oracle
- [And more](https://documentation.red-gate.com/flyway/getting-started-with-flyway/system-requirements/supported-databases-and-versions)

However, the drift check and snapshot generation are only supported for databases with [advanced comparison capability support](https://documentation.red-gate.com/flyway/flyway-concepts/database-comparisons).

## License

MIT
