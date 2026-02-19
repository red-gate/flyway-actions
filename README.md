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
          target-environment: production
          target-user: "${{ secrets.FLYWAY_USER }}"
          target-password: "${{ secrets.FLYWAY_PASSWORD }}"
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
```

The checks action automatically uploads the HTML report as a workflow artifact named `flyway-report`. See [Report Upload](#report-upload) for customization options.

### Manual review between checks and deployment (Flyway Enterprise)

Split checks and deployment into separate jobs and use a [GitHub environment with required reviewers](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment#required-reviewers) on the 'deploy' job. The deployment will pause until a reviewer approves it.

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

#### Setting up the environments

The manual review workflow uses two GitHub environments to separate read-only checks from write access deployment:

1. **`production-read-only`** — used by the `checks` job. Go to *Settings > Environments > New environment*, name it `production-read-only`, and add the following secrets:
   - `FLYWAY_USER`, `FLYWAY_PASSWORD` — database credentials with **read-only** access to the production database
   - `FLYWAY_BUILD_USER`, `FLYWAY_BUILD_PASSWORD` — credentials for the build database

   This environment does not need protection rules since it only performs read-only checks. Using a read-only database user here ensures the checks job cannot modify production data.

2. **`production-write`** — used by the `deploy` job. Create a second environment named `production-write` and add the following secrets:
   - `FLYWAY_USER`, `FLYWAY_PASSWORD` — database credentials with **write** access to the production database

   Under *Protection rules*, enable **Required reviewers** and add the team members who should approve deployments. You can also restrict which branches can deploy by enabling **Deployment branches and tags** and limiting it to `main`.

The `deploy` job will wait for reviewer approval after the `checks` job passes, giving reviewers a chance to inspect the check results and uploaded report before the migration runs.

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

## Report Upload

The `migrations/checks` action automatically uploads the Flyway HTML report as a workflow artifact after checks complete. The report is uploaded even if checks fail, so you can always inspect the results.

| Input                      | Description                                          | Default          |
|----------------------------|------------------------------------------------------|------------------|
| `report-name`              | Name for the report artifact                         | `flyway-report`  |
| `report-retention-days`    | Number of days to retain the report artifact         | `7`              |
| `skip-html-report-upload`  | Skip uploading the HTML report                       | `false`          |

### Customizing the report artifact

```yaml
- uses: red-gate/flyway-actions/migrations/checks@v1
  with:
    target-environment: production
    working-directory: my-flyway-project
    report-name: flyway-report-production
    report-retention-days: '7'
```

### Disabling the report upload

```yaml
- uses: red-gate/flyway-actions/migrations/checks@v1
  with:
    target-environment: production
    working-directory: my-flyway-project
    skip-html-report-upload: 'true'
```

### Matrix jobs

When running checks across multiple OSes in a matrix, use a unique `report-name` per job to avoid artifact name conflicts:

```yaml
strategy:
  matrix:
    os: [ubuntu-latest, windows-latest]
runs-on: ${{ matrix.os }}
steps:
  - uses: red-gate/flyway-actions/migrations/checks@v1
    with:
      target-environment: production
      working-directory: my-flyway-project
      report-name: flyway-report-${{ matrix.os }}
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
