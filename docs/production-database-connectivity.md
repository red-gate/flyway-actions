# Connecting to Production Databases

GitHub Actions workflows need network access to your database to run checks and deployments. Production databases are typically behind firewalls or private networks that GitHub-hosted runners cannot reach by default. This page covers the main approaches for establishing connectivity and the trade-offs of each.

For general background, see the GitHub docs on [connecting to a private network](https://docs.github.com/en/actions/using-github-hosted-runners/connecting-to-a-private-network) and [deploying with GitHub Actions](https://docs.github.com/actions/deployment/about-deployments/deploying-with-github-actions). The guidance below is specific to database connections and Flyway workflows.

## Self-Hosted Runners

Deploy [self-hosted runners](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners) inside your private network so they can reach your database directly.

**Advantages:**
- Full access to internal databases without exposing them to the internet
- You control the runner environment, OS, and installed tools
- No additional networking infrastructure required

**Considerations:**
- You are responsible for patching, updating, and securing the runner machines
- Runners execute workflow code, so treat them as part of your security boundary — a compromised workflow can access anything the runner can reach
- Use [runner groups](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/managing-access-to-self-hosted-runners-using-groups) to restrict which repositories and workflows can target production runners
- Prefer ephemeral runners (e.g. container-based or auto-scaling) to avoid state leaking between workflow runs

## GitHub-Hosted Runners with Private Networking

[GitHub-hosted larger runners](https://docs.github.com/en/actions/using-github-hosted-runners/connecting-to-a-private-network/about-private-networking-with-github-hosted-runners) (GitHub Enterprise Cloud) can be connected to an Azure Virtual Network, giving them direct access to resources in your private network.

**Advantages:**
- GitHub manages the runner infrastructure — no patching or maintenance
- Runners are ephemeral by default, reducing the risk of state leaking between runs
- Works with Azure-peered networks, including connections back to on-premises infrastructure via ExpressRoute or VPN gateways

**Considerations:**
- Requires GitHub Enterprise Cloud and Azure
- Network configuration is managed at the GitHub organization level

## VPN or Tunnel from Runner

Establish a VPN connection or SSH tunnel from the runner to your private network as a workflow step before running Flyway.

**Advantages:**
- Works with GitHub-hosted runners without requiring Enterprise Cloud
- Can be used with any VPN provider or bastion host

**Considerations:**
- VPN credentials must be stored as GitHub secrets and rotated regularly
- Adds complexity and latency to each workflow run
- The VPN or tunnel step can be a point of failure — ensure your workflow handles connection errors gracefully
- Audit which workflows have access to the VPN secrets

## IP Allowlisting

Allow connections from GitHub-hosted runner IP ranges through your database firewall. GitHub publishes its current IP ranges via the [meta API](https://api.github.com/meta).

**Advantages:**
- No additional infrastructure or software required
- Simple to set up for databases that are already internet-accessible with firewall rules

**Considerations:**
- GitHub's IP ranges are broad and shared across all GitHub Actions customers — allowlisting them does not restrict access to your workflows alone
- The IP ranges change over time, requiring ongoing maintenance of your firewall rules
- Exposing your database to a wide set of IPs increases the attack surface — combine this with strong authentication, TLS, and minimal database permissions

## General Recommendations

Regardless of which connectivity approach you choose:

- **Use dedicated database credentials** with the minimum permissions required. Read-only credentials for check jobs, write credentials only for deployment jobs. See the [manual review workflow](../README.md#manual-review-between-checks-and-deployment-flyway-enterprise) for an example of this separation.
- **Require TLS** for all database connections. Most JDBC drivers support this via URL parameters (e.g. `?sslmode=require` for PostgreSQL, `?encrypt=true` for SQL Server).
- **Use GitHub environment protection rules** to control which branches and people can trigger production deployments. See [Setting up the environments](../README.md#setting-up-the-environments) in the main README.
- **Monitor database connections** from your CI/CD pipeline. Set up alerts for unexpected connection sources or failed authentication attempts.
- **Test connectivity in a non-production environment first** before configuring production workflows.
