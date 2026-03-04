import type { DatabaseType } from "./database-config.js";
import { execSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as core from "@actions/core";
import { getDockerConfig, parseDatabaseType, parseJdbcUrl, probeTargetVersion } from "./database-config.js";

type ProvisionedDatabase = {
  jdbcUrl: string;
  user: string;
  password: string;
  cleanup: () => Promise<void>;
};

const provisionSqlite = (): ProvisionedDatabase => {
  const dbFile = path.join(os.tmpdir(), `flyway_build_${Date.now()}.db`);

  return {
    jdbcUrl: `jdbc:sqlite:${dbFile}`,
    user: "",
    password: "",
    cleanup: () => {
      fs.rmSync(dbFile, { force: true });
      return Promise.resolve();
    },
  };
};

const buildDockerRunArgs = (
  containerName: string,
  image: string,
  env: Record<string, string>,
  healthCmd: string,
): string => {
  const envArgs = Object.entries(env)
    .map(([k, v]) => `-e ${k}=${v}`)
    .join(" ");
  return (
    `docker run -d --name ${containerName} -P` +
    ` --health-cmd="${healthCmd}"` +
    ` --health-interval=2s --health-timeout=5s --health-retries=60` +
    ` ${envArgs} ${image}`
  );
};

const waitForHealthy = (containerName: string, maxAttempts: number = 120): void => {
  for (let i = 0; i < maxAttempts; i++) {
    const status = execSync(`docker inspect --format={{.State.Health.Status}} ${containerName}`, {
      stdio: "pipe",
      encoding: "utf-8",
    }).trim();
    if (status === "healthy") {
      return;
    }
    if (status === "unhealthy") {
      execSync(`docker rm -f ${containerName}`, { stdio: "pipe" });
      throw new Error("Container became unhealthy");
    }
    if (i === maxAttempts - 1) {
      execSync(`docker rm -f ${containerName}`, { stdio: "pipe" });
      throw new Error("Container did not become healthy in time");
    }
    execSync("sleep 1", { stdio: "pipe" });
  }
};

const getContainerPort = (containerName: string, containerPort: number): number => {
  const portOutput = execSync(`docker port ${containerName} ${containerPort}`, {
    stdio: "pipe",
    encoding: "utf-8",
  }).trim();
  return parseInt(portOutput.split(":").pop()!, 10);
};

const provisionDockerContainer = (
  dbType: Exclude<DatabaseType, "sqlite">,
  targetUrl: string,
  targetUser?: string,
  targetPassword?: string,
): ProvisionedDatabase => {
  const config = getDockerConfig(dbType);
  const conn = parseJdbcUrl(targetUrl);

  let version: string | undefined;
  if (conn) {
    core.info(`Probing ${dbType} target version at ${conn.host}:${conn.port}...`);
    version = probeTargetVersion(dbType, conn, targetUser, targetPassword);
    if (version) {
      core.info(`Detected ${dbType} version: ${version}`);
    } else {
      core.info(`Could not detect ${dbType} version, using default image`);
    }
  }

  const image = config.resolveImage(version);
  const containerName = `flyway_build_${Date.now()}`;

  core.info(`Starting ${dbType} container: ${image}`);
  const runCmd = buildDockerRunArgs(containerName, image, config.containerEnv, config.healthCmd);
  execSync(runCmd, { stdio: "pipe" });

  waitForHealthy(containerName);

  const mappedPort = getContainerPort(containerName, config.defaultPort);
  const jdbcUrl = config.buildJdbcUrl("localhost", mappedPort, config.database);

  return {
    jdbcUrl,
    user: config.user,
    password: config.password,
    cleanup: () => {
      execSync(`docker rm -f ${containerName}`, { stdio: "pipe" });
      return Promise.resolve();
    },
  };
};

const provisionBuildDatabase = (
  targetUrl: string,
  targetUser?: string,
  targetPassword?: string,
): ProvisionedDatabase | undefined => {
  const dbType = parseDatabaseType(targetUrl);
  if (!dbType) {
    return undefined;
  }

  if (dbType === "sqlite") {
    return provisionSqlite();
  }

  return provisionDockerContainer(dbType, targetUrl, targetUser, targetPassword);
};

export { provisionBuildDatabase };
export type { ProvisionedDatabase };
