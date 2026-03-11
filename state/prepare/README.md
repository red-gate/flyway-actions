# Flyway State Prepare Action

A GitHub Action to generate a Flyway state-based deployment script by comparing your schema model against a target database.

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
| `working-directory`  | Working directory for Flyway                     | No                                       |           |
| `extra-args`         | Additional Flyway CLI arguments                  | No                                       |           |

## Outputs

| Output             | Description                              |
|--------------------|------------------------------------------|
| `exit-code`        | Flyway exit code                         |
| `script-path`      | Path to the generated deployment script  |
| `undo-script-path` | Path to the generated undo script        |

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

## License

MIT
