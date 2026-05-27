# Redgate Flyway GitHub Actions

<p align="center">
  <img src="https://documentation.red-gate.com/download/attachments/138346876/FD?version=3&modificationDate=1633982869952&api=v2" alt="Flyway" height="80">
</p>

### Set up, check, and deploy changes with Redgate Flyway

[![CI](https://github.com/red-gate/flyway-actions/actions/workflows/ci.yml/badge.svg)](https://github.com/red-gate/flyway-actions/actions/workflows/ci.yml)
[![End-to-End Tests](https://github.com/red-gate/flyway-actions/actions/workflows/end-to-end-test.yml/badge.svg)](https://github.com/red-gate/flyway-actions/actions/workflows/end-to-end-test.yml)

---

These actions allow you to safely deploy database schema changes to your databases using [Redgate Flyway](https://www.red-gate.com/products/flyway/).
Supports 50+ databases including PostgreSQL, MySQL, SQL Server, and Oracle.

These actions can be used both for database deployment pipelines, and for validation of your PRs.

## Actions

| Action                                                     | Description                                                 |
|------------------------------------------------------------|-------------------------------------------------------------|
| [`setup-flyway`](https://github.com/red-gate/setup-flyway) | Install Flyway CLI in your GitHub Actions workflow          |
| [`migrations/checks`](migrations/checks)                   | Run pre-deployment checks on migrations and target database |
| [`migrations/deploy`](migrations/deploy)                   | Deploy pending migrations against target database           |
| [`migrations/generate`](migrations/generate)               | Generate migrations from your schema model                  |
| [`migrations/undo`](migrations/undo)                       | Undo migrations on target database                          |
| [`state/prepare`](state/prepare)                           | Generate deployment script and run pre-deployment checks    |
| [`state/deploy`](state/deploy)                             | Deploy state-based changes to target database               |

## Usage

> **Tip:** You can generate a ready-to-run GitHub Actions workflow from Flyway Desktop's [Automated Deployment page](https://documentation.red-gate.com/fd/tutorial-generate-a-github-actions-deployment-workflow-with-flyway-desktop-342852947.html). See also [Automating deployment using a CI/CD tool](https://documentation.red-gate.com/fd/automating-deployment-using-a-ci-cd-tool-311660904.html).

- [Deployment usage examples](docs/deployment-usage-examples.md) — applying changes to target databases (migrations and state, automated and manual-review variants, Enterprise and Community)
- [Development workflow usage examples](docs/development-usage-examples.md) — supporting authoring, e.g. auto-generating migrations on a pull request

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
  uses: red-gate/flyway-actions/migrations/deploy@v2
  with:
    target-environment: production
    target-user: "${{ secrets.FLYWAY_USER }}"
    target-password: "${{ secrets.FLYWAY_PASSWORD }}"
```

- **Secrets are masked in logs** — GitHub automatically redacts secret values from workflow output, but avoid echoing or writing them to files.
- **Limit secret scope with environments** — attach secrets to environments that have [protection rules](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment#environment-protection-rules) (e.g. required reviewers, branch restrictions) to control who can trigger deployments that use those secrets.
- **Pass secrets explicitly** — GitHub does not inject secrets automatically. Each step that needs a secret must reference it via `with` or `env`.

## Production Database Connectivity

See [Connecting to Production Databases](docs/production-database-connectivity.md) for guidance on establishing network access between GitHub Actions runners and production databases.

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
