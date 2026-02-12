# flyway-github-actions

<p align="center">
  <img src="https://documentation.red-gate.com/download/attachments/138346876/FD?version=3&modificationDate=1633982869952&api=v2" alt="Flyway" height="80">
</p>

### Deploy database changes with confidence

[![CI](../../actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)
[![End-to-End Tests](../../actions/workflows/test-action.yml/badge.svg)](../../actions/workflows/test-action.yml)

## Actions

| Action                                                 | Description                                       |
|--------------------------------------------------------|---------------------------------------------------|
| [`flyway/migrations/deploy`](flyway/migrations/deploy) | Deploy pending migrations against target database |

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
      - name: Run migrations deployment
        uses: red-gate/flyway-actions/migrations/deploy@v1
        with:
          target-environment: production
          target-user: "${{ secrets.FLYWAY_USER }}"
          target-password: "${{ secrets.FLYWAY_PASSWORD }}"
          working-directory: my-flyway-project
```

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