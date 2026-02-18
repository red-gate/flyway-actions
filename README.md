# Redgate Flyway GitHub Actions

<p align="center">
  <img src="https://documentation.red-gate.com/download/attachments/138346876/FD?version=3&modificationDate=1633982869952&api=v2" alt="Flyway" height="80">
</p>

### Deploy database changes with confidence

[![CI](https://github.com/red-gate/flyway-actions/actions/workflows/ci.yml/badge.svg)](https://github.com/red-gate/flyway-actions/actions/workflows/ci.yml)
[![End-to-End Tests](https://github.com/red-gate/flyway-actions/actions/workflows/end-to-end-test.yml/badge.svg)](https://github.com/red-gate/flyway-actions/actions/workflows/end-to-end-test.yml)

---

These actions allow you to safely deploy database schema changes to your databases using [Redgate Flyway](https://www.red-gate.com/products/flyway/).
Supports 50+ databases including PostgreSQL, MySQL, SQL Server, and Oracle.

## Actions

| Action                                    | Description                                       |
|-------------------------------------------|---------------------------------------------------|
| [`migrations/deploy`](migrations/deploy)  | Deploy pending migrations against target database |

## Usage

### Automated deployment using migrations (Flyway Enterprise)
```yaml
name: Deploy to production

on:
  push:
    branches: [main]

jobs:
  automated-deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - name: Checkout
        uses: actions/checkout@v6
      - name: Setup Flyway
        uses: red-gate/setup-flyway@v3
        with:
          edition: enterprise
          i-agree-to-the-eula: true
          email: "${{ secrets.FLYWAY_EMAIL }}"
          token: "${{ secrets.FLYWAY_TOKEN }}"
      - name: Run deployment checks and generate reports
        uses: red-gate/flyway-actions/migrations/checks@v1
        with:
          environment: production
          user: "${{ secrets.FLYWAY_USER }}"
          password: "${{ secrets.FLYWAY_PASSWORD }}"
          build-environment: build
          build-user: "${{ secrets.FLYWAY_BUILD_USER }}"
          build-password: "${{ secrets.FLYWAY_BUILD_PASSWORD }}"
          working-directory: my-flyway-project
      - name: Run migrations deployment
        uses: red-gate/flyway-actions/migrations/deploy@v1
        with:
          target-environment: production
          target-user: "${{ secrets.FLYWAY_USER }}"
          target-password: "${{ secrets.FLYWAY_PASSWORD }}"
          working-directory: my-flyway-project
      - name: Upload Flyway pre-deployment report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: flyway-report
          path: my-flyway-project/report.html
          retention-days: 1
```

### Manual review between checks and deployment (Flyway Enterprise)

Split checks and deployment into separate jobs and use a [GitHub environment with required reviewers](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment#required-reviewers) on the deploy job. The deployment will pause until a reviewer approves it.

```yaml
name: Deploy to production

on:
  push:
    branches: [main]

jobs:
  checks:
    runs-on: ubuntu-latest
    environment: production-read-only
    steps:
      - name: Checkout
        uses: actions/checkout@v6
      - name: Setup Flyway
        uses: red-gate/setup-flyway@v3
        with:
          edition: enterprise
          i-agree-to-the-eula: true
          email: "${{ secrets.FLYWAY_EMAIL }}"
          token: "${{ secrets.FLYWAY_TOKEN }}"
      - name: Run checks
        uses: red-gate/flyway-actions/migrations/checks@v1
        with:
          target-environment: production
          target-user: "${{ secrets.FLYWAY_USER }}"
          target-password: "${{ secrets.FLYWAY_PASSWORD }}"
          build-environment: build
          build-user: "${{ secrets.FLYWAY_BUILD_USER }}"
          build-password: "${{ secrets.FLYWAY_BUILD_PASSWORD }}"
          working-directory: my-flyway-project
      - name: Upload Flyway pre-deployment report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: flyway-report
          path: my-flyway-project/report.html
          retention-days: 1
  deploy:
    needs: checks
    runs-on: ubuntu-latest
    environment: production-write  # requires reviewer approval before running
    steps:
      - name: Checkout
        uses: actions/checkout@v6
      - name: Setup Flyway
        uses: red-gate/setup-flyway@v3
        with:
          edition: enterprise
          i-agree-to-the-eula: true
          email: "${{ secrets.FLYWAY_EMAIL }}"
          token: "${{ secrets.FLYWAY_TOKEN }}"
      - name: Run migrations deployment
        uses: red-gate/flyway-actions/migrations/deploy@v1
        with:
          target-environment: production
          target-user: "${{ secrets.FLYWAY_USER }}"
          target-password: "${{ secrets.FLYWAY_PASSWORD }}"
          working-directory: my-flyway-project
```

To configure the approval gate, go to *Settings > Environments > production* and add required reviewers under protection rules. The `deploy` job will wait for approval after `checks` passes.

### Flyway Community deployment
```yaml
name: Deploy to production

on:
  push:
    branches: [main]

jobs:
  automated-deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - name: Checkout
        uses: actions/checkout@v6
      - name: Setup Flyway
        uses: red-gate/setup-flyway@v3
        with:
          edition: community
          i-agree-to-the-eula: true
      - name: Run migrations deployment
        uses: red-gate/flyway-actions/migrations/deploy@v1
        with:
          target-environment: production
          target-user: "${{ secrets.FLYWAY_USER }}"
          target-password: "${{ secrets.FLYWAY_PASSWORD }}"
          working-directory: my-flyway-project
```

## Best Practices for Secrets

GitHub Actions secrets keep sensitive values like database credentials and license tokens out of your workflow files and logs.

### Storing Secrets

- **Use repository or organization secrets** — navigate to *Settings > Secrets and variables > Actions* to add secrets. Organization-level secrets can be shared across repositories.
- **Use environment secrets for sensitive targets** — for production databases, store credentials under a [GitHub environment](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment) (e.g. `production`). This scopes secrets to that environment and enables protection rules like required reviewers.
- **Never hardcode credentials** — keep database URLs, usernames, passwords, and Flyway license tokens in secrets rather than in workflow files, `flyway.toml`, or source code.
- **Rotate secrets regularly** — update secrets when team members leave or if a credential may have been exposed.

### Accessing Secrets in Workflows

Reference secrets using the `${{ secrets.SECRET_NAME }}` syntax:

```yaml
- name: Run migrations deployment
  uses: red-gate/flyway-actions/migrations/deploy@v1
  with:
    target-environment: production
    target-user: "${{ secrets.FLYWAY_USER }}"
    target-password: "${{ secrets.FLYWAY_PASSWORD }}"
```

- **Secrets are masked in logs** — GitHub automatically redacts secret values from workflow output, but avoid echoing or writing them to files.
- **Limit secret scope with environments** — attach secrets to environments that have [protection rules](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment#environment-protection-rules) (e.g. required reviewers, branch restrictions) to control who can trigger deployments that use those secrets.
- **Pass secrets explicitly** — GitHub does not inject secrets automatically. Each step that needs a secret must reference it via `with` or `env`.

## License

The scripts and documentation in this project are released under the [MIT License](LICENSE.md).

## Contributions

Contributions are welcome! See [Code of Conduct](.github/CODE_OF_CONDUCT.md)

## Breaking Changes

See [Breaking Changes](docs/BREAKING_CHANGES.md) for a list of breaking changes.

## Security Policy

Find a security issue? Please review our [Security Policy](.github/SECURITY.md).

## Support

For support, please see the [Support Policy](.github/SUPPORT.md).
