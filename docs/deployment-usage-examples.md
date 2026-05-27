# Deployment Usage Examples

Workflows that take an existing Flyway project (migrations or schema model) and apply it to a target database.

> **Tip:** You can generate a ready-to-run GitHub Actions workflow from Flyway Desktop's [Automated Deployment page](https://documentation.red-gate.com/fd/tutorial-generate-a-github-actions-deployment-workflow-with-flyway-desktop-342852947.html). See also [Automating deployment using a CI/CD tool](https://documentation.red-gate.com/fd/automating-deployment-using-a-ci-cd-tool-311660904.html).

## Automated deployment using migrations (Flyway Enterprise)

```yaml
name: Deploy to test

on:
  push:
    branches: [main]

jobs:
  automated-deploy:
    runs-on: ubuntu-latest
    environment: test
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
        uses: red-gate/flyway-actions/migrations/checks@v2
        with:
          target-environment: test
          target-user: "${{ secrets.FLYWAY_USER }}"
          target-password: "${{ secrets.FLYWAY_PASSWORD }}"
          build-environment: build
          build-user: "${{ secrets.FLYWAY_BUILD_USER }}"
          build-password: "${{ secrets.FLYWAY_BUILD_PASSWORD }}"
          working-directory: my-flyway-project
      - name: Run migrations deployment
        uses: red-gate/flyway-actions/migrations/deploy@v2
        with:
          target-environment: test
          target-user: "${{ secrets.FLYWAY_USER }}"
          target-password: "${{ secrets.FLYWAY_PASSWORD }}"
          working-directory: my-flyway-project
```

## Manual review between checks and deployment (Flyway Enterprise)

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
        uses: red-gate/flyway-actions/migrations/checks@v2
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
        uses: red-gate/flyway-actions/migrations/deploy@v2
        with:
          target-environment: production
          target-user: "${{ secrets.FLYWAY_USER }}"
          target-password: "${{ secrets.FLYWAY_PASSWORD }}"
          working-directory: my-flyway-project
```

### Setting up the environments

The manual review workflow uses two GitHub environments to separate read-only checks from write access deployment:

1. **`production-read-only`** — used by the `checks` job. Go to *Settings > Environments > New environment*, name it `production-read-only`, and add the following secrets:
   - `FLYWAY_USER`, `FLYWAY_PASSWORD` — database credentials with **read-only** access to the production database
   - `FLYWAY_BUILD_USER`, `FLYWAY_BUILD_PASSWORD` — credentials for the build database

   This environment does not need protection rules since it only performs read-only checks. Using a read-only database user here ensures the checks job cannot modify production data.

2. **`production-write`** — used by the `deploy` job. Create a second environment named `production-write` and add the following secrets:
   - `FLYWAY_USER`, `FLYWAY_PASSWORD` — database credentials with **write** access to the production database

   Under *Protection rules*, enable **Required reviewers** and add the team members who should approve deployments. You can also restrict which branches can deploy by enabling **Deployment branches and tags** and limiting it to `main`.

The `deploy` job will wait for reviewer approval after the `checks` job passes, giving reviewers a chance to inspect the check results and uploaded report before the migration runs.

## Automated deployment using state (Flyway Enterprise)

State-based deployments use `state/prepare` to generate a deployment script by comparing your schema model against the target database, then `state/deploy` to apply it. This approach is ideal when you manage your database schema as a set of object definitions rather than ordered migration files.

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
      - name: Prepare deployment script
        uses: red-gate/flyway-actions/state/prepare@v2
        with:
          target-environment: production
          target-user: "${{ secrets.FLYWAY_USER }}"
          target-password: "${{ secrets.FLYWAY_PASSWORD }}"
          working-directory: my-flyway-project
      - name: Deploy changes
        uses: red-gate/flyway-actions/state/deploy@v2
        with:
          target-environment: production
          target-user: "${{ secrets.FLYWAY_USER }}"
          target-password: "${{ secrets.FLYWAY_PASSWORD }}"
          working-directory: my-flyway-project
```

## Manual review between prepare and deployment using state (Flyway Enterprise)

Split the prepare and deploy steps into separate jobs. Use a [GitHub environment with required reviewers](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment#required-reviewers) on the deploy job so a reviewer can inspect the pre-deployment report and generated deployment script before approving.

```yaml
name: Deploy to production

on:
  push:
    branches: [main]

jobs:
  prepare:
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
      - name: Prepare deployment script
        uses: red-gate/flyway-actions/state/prepare@v2
        with:
          target-environment: production
          target-user: "${{ secrets.FLYWAY_USER }}"
          target-password: "${{ secrets.FLYWAY_PASSWORD }}"
          working-directory: my-flyway-project
  deploy:
    needs: prepare
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
      - name: Deploy changes
        uses: red-gate/flyway-actions/state/deploy@v2
        with:
          target-environment: production
          target-user: "${{ secrets.FLYWAY_USER }}"
          target-password: "${{ secrets.FLYWAY_PASSWORD }}"
          working-directory: my-flyway-project
```

The environment setup is the same as described in [Setting up the environments](#setting-up-the-environments) above. The `prepare` job runs drift detection, code review, and generates reports and the deployment script — all using read-only access. Reviewers can inspect the uploaded pre-deployment report and deployment script artifacts before approving the `deploy` job.

## Flyway Community deployment

```yaml
name: Deploy to production

on:
  push:
    branches: [ main ]

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
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.x'
      - name: Install SQLFluff
        run: pip install sqlfluff
      - name: Run checks
        uses: red-gate/flyway-actions/migrations/checks@v2
        with:
          target-environment: production
          target-user: "${{ secrets.FLYWAY_USER }}"
          target-password: "${{ secrets.FLYWAY_PASSWORD }}"
          working-directory: my-flyway-project
      - name: Run migrations deployment
        uses: red-gate/flyway-actions/migrations/deploy@v2
        with:
          target-environment: production
          target-user: "${{ secrets.FLYWAY_USER }}"
          target-password: "${{ secrets.FLYWAY_PASSWORD }}"
          working-directory: my-flyway-project
```
