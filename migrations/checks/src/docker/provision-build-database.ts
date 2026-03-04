import type { DatabaseType } from "./database-config.js";
import * as core from "@actions/core";
import { getDatabaseConfig, parseDatabaseType } from "./database-config.js";

type ProvisionedDatabase = {
  jdbcUrl: string;
  user: string;
  password: string;
  cleanup: () => Promise<void>;
};

type ContainerInfo = {
  host: string;
  port: number;
  database: string;
  user: string;
  password: string;
  stop: () => Promise<unknown>;
};

const startPostgresContainer = async (): Promise<ContainerInfo> => {
  const { PostgreSqlContainer } = await import("@testcontainers/postgresql");
  const config = getDatabaseConfig("postgresql");
  const container = await new PostgreSqlContainer(config.image)
    .withDatabase("flyway_build")
    .withUsername("test")
    .withPassword("test")
    .start();
  return {
    host: container.getHost(),
    port: container.getPort(),
    database: container.getDatabase(),
    user: container.getUsername(),
    password: container.getPassword(),
    stop: () => container.stop(),
  };
};

const startSqlServerContainer = async (): Promise<ContainerInfo> => {
  const { MSSQLServerContainer } = await import("@testcontainers/mssqlserver");
  const config = getDatabaseConfig("sqlserver");
  const container = await new MSSQLServerContainer(config.image).acceptLicense().start();
  return {
    host: container.getHost(),
    port: container.getPort(),
    database: container.getDatabase(),
    user: container.getUsername(),
    password: container.getPassword(),
    stop: () => container.stop(),
  };
};

const startMySqlContainer = async (): Promise<ContainerInfo> => {
  const { MySqlContainer } = await import("@testcontainers/mysql");
  const config = getDatabaseConfig("mysql");
  const container = await new MySqlContainer(config.image)
    .withDatabase("flyway_build")
    .withUsername("test")
    .withUserPassword("test")
    .start();
  return {
    host: container.getHost(),
    port: container.getPort(),
    database: container.getDatabase(),
    user: container.getUsername(),
    password: container.getUserPassword(),
    stop: () => container.stop(),
  };
};

const startOracleContainer = async (): Promise<ContainerInfo> => {
  const { GenericContainer, Wait } = await import("testcontainers");
  const config = getDatabaseConfig("oracle");
  const container = await new GenericContainer(config.image)
    .withExposedPorts(config.defaultPort)
    .withEnvironment({
      ORACLE_PASSWORD: config.defaultPassword,
    })
    .withWaitStrategy(Wait.forHealthCheck())
    .start();
  return {
    host: container.getHost(),
    port: container.getMappedPort(config.defaultPort),
    database: config.defaultDatabase,
    user: config.defaultUser,
    password: config.defaultPassword,
    stop: () => container.stop(),
  };
};

const containerStarters: Record<DatabaseType, () => Promise<ContainerInfo>> = {
  postgresql: startPostgresContainer,
  sqlserver: startSqlServerContainer,
  mysql: startMySqlContainer,
  oracle: startOracleContainer,
};

const provisionBuildDatabase = async (targetUrl: string): Promise<ProvisionedDatabase | undefined> => {
  const dbType = parseDatabaseType(targetUrl);
  if (!dbType) {
    core.info(`Auto-provisioning not available for database URL: ${targetUrl}`);
    return undefined;
  }

  core.info(`Auto-provisioning ${dbType} build database via Docker...`);

  const starter = containerStarters[dbType];
  const result = await starter();
  const config = getDatabaseConfig(dbType);
  const jdbcUrl = config.buildJdbcUrl(result.host, result.port, result.database);

  core.setSecret(result.password);
  core.info(`Build database provisioned at ${result.host}:${result.port}`);

  return {
    jdbcUrl,
    user: result.user,
    password: result.password,
    cleanup: async () => {
      try {
        await result.stop();
        core.info("Build database container stopped");
      } catch (err) {
        core.warning(`Failed to stop build database container: ${err}`);
      }
    },
  };
};

export { provisionBuildDatabase };
export type { ProvisionedDatabase };
