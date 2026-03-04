import { execSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { constructBuildUrl, getOracleDockerConfig, parseDatabaseType } from "./database-config.js";

type ProvisionedDatabase = {
  jdbcUrl: string;
  user: string;
  password: string;
  provisioner?: string;
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

const provisionWithCreateDatabase = (
  targetUrl: string,
  targetUser?: string,
  targetPassword?: string,
): ProvisionedDatabase | undefined => {
  const buildUrl = constructBuildUrl(targetUrl);
  if (!buildUrl) {
    return undefined;
  }

  return {
    jdbcUrl: buildUrl,
    user: targetUser ?? "",
    password: targetPassword ?? "",
    provisioner: "create-database",
    cleanup: () => Promise.resolve(),
  };
};

const provisionOracleContainer = (): ProvisionedDatabase => {
  const config = getOracleDockerConfig();
  const containerId = `flyway_build_${Date.now()}`;
  const containerName = containerId;

  execSync(`docker run -d --name ${containerName} -P -e ORACLE_PASSWORD=${config.defaultPassword} ${config.image}`, {
    stdio: "pipe",
  });

  const maxAttempts = 120;
  for (let i = 0; i < maxAttempts; i++) {
    const status = execSync(`docker inspect --format={{.State.Health.Status}} ${containerName}`, {
      stdio: "pipe",
      encoding: "utf-8",
    }).trim();
    if (status === "healthy") {
      break;
    }
    if (i === maxAttempts - 1) {
      execSync(`docker rm -f ${containerName}`, { stdio: "pipe" });
      throw new Error("Oracle container did not become healthy in time");
    }
    execSync("sleep 1", { stdio: "pipe" });
  }

  const portOutput = execSync(`docker port ${containerName} ${config.defaultPort}`, {
    stdio: "pipe",
    encoding: "utf-8",
  }).trim();
  const mappedPort = portOutput.split(":").pop()!;

  const jdbcUrl = config.buildJdbcUrl("localhost", parseInt(mappedPort, 10), config.defaultDatabase);

  return {
    jdbcUrl,
    user: config.defaultUser,
    password: config.defaultPassword,
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

  switch (dbType) {
    case "sqlite":
      return provisionSqlite();
    case "postgresql":
    case "mysql":
    case "sqlserver":
      return provisionWithCreateDatabase(targetUrl, targetUser, targetPassword);
    case "oracle":
      return provisionOracleContainer();
  }
};

export { provisionBuildDatabase };
export type { ProvisionedDatabase };
