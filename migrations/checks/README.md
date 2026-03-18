# Flyway Migrations Checks Action

A GitHub Action to run pre-deployment checks on your Flyway migrations and target database.

This action can be used both as a validation step in deployment pipelines, and on its own for validation of your PRs.

## Behavior under different editions

### Flyway Enterprise

When running under Flyway Enterprise the following validation steps will be run by default

#### Drift detection

Compares your target database against the expected state.
Note that this will only be able to flag up drift after your first deployment, once a snapshot of the database has been captured.
This operation is only available for databases with [advanced comparison capability support](https://documentation.red-gate.com/flyway/flyway-concepts/database-comparisons).
For more information, see [the associated Flyway documentation](https://documentation.red-gate.com/flyway/flyway-concepts/drift-analysis).

#### Code review

Scan your SQL migrations for potential issues, antipatterns, or policy violations.
This will incorporate Redgate rules aimed at identifying data loss and security issues.
For more information, see [the associated Flyway documentation](https://documentation.red-gate.com/flyway/flyway-concepts/code-analysis).

#### Deployment report

A report will be generated which includes:
* the full list of drifted objects, if any
* the full list of code review violations, if any
* a detailed preview of what will change in your database, by object (requires a [build environment](https://documentation.red-gate.com/flyway/flyway-concepts/environments/shadow-and-build-environments) to be configured)
* a representation of the deployment script that will be run against your database when you run the 'migrations/deploy' action (see [dry runs](https://documentation.red-gate.com/flyway/flyway-concepts/migrations/migration-command-dry-runs))

The drift report and deployment changes report are only available for databases with [advanced comparison capability support](https://documentation.red-gate.com/flyway/flyway-concepts/database-comparisons).

### Flyway Teams

The code review will run, but without Redgate rules. You will need to configure SQLFluff manually.
The deployment report will contain the code review output and the deployment script.
The drift checks and the deployment changes report will not run.

### Flyway Community

The code review will run, but without Redgate rules.
You will need to [install SQLFluff](#installing-sqlfluff-for-community-and-teams) and configure it manually for the code review to work.
The deployment report will contain the code review output only.
The drift checks, the deployment changes report, and the deployment script generation will not run.

## Prerequisites

This action requires Flyway to be installed. Use [`red-gate/setup-flyway@v3`](https://github.com/red-gate/setup-flyway) before this action:

```yaml
- uses: red-gate/setup-flyway@v3
  with:
    edition: enterprise
    i-agree-to-the-eula: true
    email: ${{ secrets.REDGATE_EMAIL }}
    token: ${{ secrets.REDGATE_TOKEN }}
- uses: red-gate/flyway-actions/migrations/checks@v2
  with:
    target-environment: production
    target-user: ${{ secrets.DB_USER }}
    target-password: ${{ secrets.DB_PASSWORD }}
    build-environment: build
    build-user: ${{ secrets.BUILD_DB_USER }}
    build-password: ${{ secrets.BUILD_DB_PASSWORD }}
    build-ok-to-erase: true
    working-directory: my-flyway-project
```

### Installing SQLFluff for Community edition

SQLFluff is required for performing the code review step.
Flyway bundles SQLFluff in the enterprise edition but not in the community edition.
If running in community edition, you need to install it in your workflow before running the checks action, otherwise the code review step will fail.
If you prefer not to install SQLFluff, you can skip the code review by setting `skip-code-review: true`.

Add these steps to your workflow before the checks action:

```yaml
- name: Set up Python
  uses: actions/setup-python@v5
  with:
    python-version: '3.x'
- name: Install SQLFluff
  run: pip install sqlfluff
```

You can optionally add a `.sqlfluff` configuration file to your Flyway project to customize the rules and dialect.
See the [SQLFluff documentation](https://docs.sqlfluff.com/en/stable/configuration/overview.html) for more configuration options.


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
  - uses: red-gate/flyway-actions/migrations/checks@v2
    with:
      target-environment: production
      target-user: ${{ secrets.DB_USER }}
      target-password: ${{ secrets.DB_PASSWORD }}
      working-directory: my-flyway-project
```

### With Build Database (for Deployment Changes Report)

Provide a build database to enable the deployment changes report. The build database is a temporary database that Flyway uses to simulate the deployment.

```yaml
- uses: red-gate/flyway-actions/migrations/checks@v2
  with:
    target-environment: production
    target-user: ${{ secrets.DB_USER }}
    target-password: ${{ secrets.DB_PASSWORD }}
    build-environment: build
    build-user: ${{ secrets.BUILD_DB_USER }}
    build-password: ${{ secrets.BUILD_DB_PASSWORD }}
    build-ok-to-erase: true
    working-directory: my-flyway-project
```

### Skipping Specific Checks

```yaml
- uses: red-gate/flyway-actions/migrations/checks@v2
  with:
    target-environment: production
    target-user: ${{ secrets.DB_USER }}
    target-password: ${{ secrets.DB_PASSWORD }}
    skip-code-review: true
    skip-drift-check: true
```

### Continue on Failure

By default, the action fails when drift is detected or code review violations are found. Set `fail-on-drift` or `fail-on-code-review` to `false` to continue:

```yaml
- uses: red-gate/flyway-actions/migrations/checks@v2
  with:
    target-environment: production
    target-user: ${{ secrets.DB_USER }}
    target-password: ${{ secrets.DB_PASSWORD }}
    fail-on-drift: false
    fail-on-code-review: false
```

### With Cherry-Pick

```yaml
- uses: red-gate/flyway-actions/migrations/checks@v2
  with:
    target-environment: production
    target-user: ${{ secrets.DB_USER }}
    target-password: ${{ secrets.DB_PASSWORD }}
    cherry-pick: '2.0,2.1,3.0'
```

## Checks

This action runs the following pre-deployment checks:

| Check                         | Description                                                     | Requires Build Database |
|-------------------------------|-----------------------------------------------------------------|-------------------------|
| **Drift Check**               | Detects unexpected changes made directly to the target database | No                      |
| **Code Review**               | Validates migration scripts against coding rules                | No                      |
| **Deployment Changes Report** | Generates a report of the changes that will be applied          | Yes                     |
| **Deployment Script Review**  | Reviews the deployment script via a dry run                     | No                      |

## Inputs

### Target Database

| Input                      | Description                                | Required                                 | Default     |
|----------------------------|--------------------------------------------|------------------------------------------|-------------|
| `target-environment`       | Target database to check                   | Required if `target-url` not set         | `default`   |
| `target-url`               | JDBC URL for the target database           | Required if `target-environment` not set |             |
| `target-user`              | Database user for the target database      | No                                       |             |
| `target-password`          | Database password for the target database  | No                                       |             |
| `target-schemas`           | Comma-separated list of schemas            | No                                       |             |
| `target-migration-version` | Migrate up to this version for dry run     | No                                       |             |
| `cherry-pick`              | Comma-separated list of migration versions | No                                       |             |

### Build Database

A build database is required for the deployment changes report. If no build database is configured, this step will be skipped.

| Input               | Description                                                                            | Required                                                                                                                              | Default |
|---------------------|----------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------|---------|
| `build-environment` | Build database for generating a deployment changes report                              | No                                                                                                                                    |         |
| `build-url`         | JDBC URL for the build database                                                        | No                                                                                                                                    |         |
| `build-user`        | Database user for the build database                                                   | No                                                                                                                                    |         |
| `build-password`    | Database password for the build database                                               | No                                                                                                                                    |         |
| `build-schemas`     | Comma-separated list of schemas for the build database                                 | No                                                                                                                                    |         |
| `build-ok-to-erase` | Allow Flyway to erase the build database. This will delete all schema and data objects | Required if build database is configured but `build-environment` not set or build environment does not have a provisioner configured. | `false` |

### Check Options

| Input                            | Description                                                      | Required | Default |
|----------------------------------|------------------------------------------------------------------|----------|---------|
| `skip-code-review`               | Skip the code review check                                       | No       | `false` |
| `skip-drift-check`               | Skip the drift check                                             | No       | `false` |
| `skip-deployment-changes-report` | Skip the deployment changes report                               | No       | `false` |
| `skip-deployment-script-review`  | Skip the deployment script review (dry run)                      | No       | `false` |
| `fail-on-code-review`            | Whether to fail the action when code review violations are found | No       | `true`  |
| `fail-on-drift`                  | Whether to fail the action when drift is detected                | No       | `true`  |

### Report Upload

The pre-deployment report is automatically uploaded as a workflow artifact after checks complete (even if checks fail).

| Input                                  | Description                                                 | Required | Default                        |
|----------------------------------------|-------------------------------------------------------------|----------|--------------------------------|
| `pre-deployment-report-name`           | Name for the pre-deployment report artifact                 | No       | `flyway-pre-deployment-report` |
| `pre-deployment-report-retention-days` | Number of days to retain the pre-deployment report artifact | No       | `7`                            |
| `skip-pre-deployment-report-upload`    | Skip uploading the pre-deployment report                    | No       | `false`                        |

If the 'checks' action runs more than once in the same workflow (e.g. against multiple target databases), use a unique `pre-deployment-report-name` for each run to avoid artifact name conflicts:

```yaml
strategy:
  matrix:
    target: [staging, production]
steps:
  - uses: red-gate/flyway-actions/migrations/checks@v2
    with:
      target-environment: ${{ matrix.target }}
      working-directory: my-flyway-project
      pre-deployment-report-name: flyway-pre-deployment-report-${{ matrix.target }}
```

### Drift Resolution Script Upload

When drift is detected, Flyway generates resolution scripts that can be used to bring the target database back in line with the expected state. These scripts are automatically uploaded as a workflow artifact.

| Input                                    | Description                                                    | Required | Default                            |
|------------------------------------------|----------------------------------------------------------------|----------|------------------------------------|
| `drift-resolution-scripts-name`          | Name for the drift resolution scripts artifact                 | No       | `flyway-drift-resolution-scripts`  |
| `drift-resolution-scripts-retention-days`| Number of days to retain the drift resolution scripts artifact | No       | `7`                                |
| `skip-drift-resolution-scripts-upload`   | Skip uploading drift resolution scripts                        | No       | `false`                            |

If the checks action runs more than once in the same workflow, use a unique `drift-resolution-scripts-name` for each run to avoid artifact name conflicts:

```yaml
strategy:
  matrix:
    target: [staging, production]
steps:
  - uses: red-gate/flyway-actions/migrations/checks@v2
    with:
      target-environment: ${{ matrix.target }}
      working-directory: my-flyway-project
      drift-resolution-scripts-name: flyway-drift-resolution-scripts-${{ matrix.target }}
```

### Other

| Input               | Description                                                    | Required | Default |
|---------------------|----------------------------------------------------------------|----------|---------|
| `working-directory` | Working directory for Flyway execution                         | No       |         |
| `extra-args`        | Additional Flyway CLI arguments (e.g. `-sqlMigrationPrefix=M`) | No       |         |

## Outputs

| Output                 | Description                                                            |
|------------------------|------------------------------------------------------------------------|
| `exit-code`            | Flyway exit code                                                       |
| `drift-detected`       | Whether drift was detected (empty if skipped)                          |
| `changed-object-count` | Number of changed objects in the deployment (empty if skipped)         |
| `code-violation-count` | Number of code review violations found (empty if skipped)              |
| `code-violation-codes` | Comma-separated list of code review violation codes (empty if skipped) |

There is currently a limitation where `code-violation-count` and `code-violation-codes` are not set on the output when `fail-on-code-review` is set to `true`.
This will be fixed in an upcoming release.

### Using Outputs

```yaml
- uses: red-gate/flyway-actions/migrations/checks@v2
  id: checks
  with:
    target-environment: production
    fail-on-drift: false
    fail-on-code-review: false
- run: |
    echo "Drift detected: ${{ steps.checks.outputs.drift-detected }}"
    echo "Code violations: ${{ steps.checks.outputs.code-violation-count }}"
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

However, the drift check and deployment changes report are only supported for databases with [advanced comparison capability support](https://documentation.red-gate.com/flyway/flyway-concepts/database-comparisons).

## License

MIT
