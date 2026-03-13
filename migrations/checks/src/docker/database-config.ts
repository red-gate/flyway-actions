import { execSync } from "node:child_process";

type DatabaseType = "postgresql" | "sqlserver" | "mysql" | "oracle" | "sqlite";

type JdbcConnectionInfo = {
  host: string;
  port: number;
  database?: string;
};

type DockerConfig = {
  resolveImage: (majorVersion?: string) => string;
  defaultPort: number;
  user: string;
  password: string;
  database: string;
  containerEnv: Record<string, string>;
  healthCmd: string;
  buildJdbcUrl: (host: string, port: number, database: string) => string;
};

const jdbcPrefixMap: { prefix: string; type: DatabaseType }[] = [
  { prefix: "jdbc:postgresql://", type: "postgresql" },
  { prefix: "jdbc:sqlserver://", type: "sqlserver" },
  { prefix: "jdbc:mysql://", type: "mysql" },
  { prefix: "jdbc:oracle:", type: "oracle" },
  { prefix: "jdbc:sqlite:", type: "sqlite" },
];

const parseDatabaseType = (jdbcUrl: string): DatabaseType | undefined =>
  jdbcPrefixMap.find((entry) => jdbcUrl.startsWith(entry.prefix))?.type;

const parseJdbcUrl = (jdbcUrl: string): JdbcConnectionInfo | undefined => {
  const dbType = parseDatabaseType(jdbcUrl);

  switch (dbType) {
    case "postgresql":
    case "mysql": {
      const prefix = dbType === "postgresql" ? "jdbc:postgresql://" : "jdbc:mysql://";
      const httpUrl = new URL(jdbcUrl.replace(prefix, "http://"));
      const defaultPort = dbType === "postgresql" ? 5432 : 3306;
      return {
        host: httpUrl.hostname,
        port: httpUrl.port ? parseInt(httpUrl.port, 10) : defaultPort,
        database: httpUrl.pathname.slice(1) || undefined,
      };
    }
    case "sqlserver": {
      const afterPrefix = jdbcUrl.replace("jdbc:sqlserver://", "");
      const hostPort = afterPrefix.split(";")[0];
      const [host, portStr] = hostPort.split(":");
      const params = afterPrefix.includes(";") ? afterPrefix.substring(afterPrefix.indexOf(";") + 1) : "";
      const dbParam = params.split(";").find((p) => p.toLowerCase().startsWith("databasename="));
      return {
        host,
        port: portStr ? parseInt(portStr, 10) : 1433,
        database: dbParam?.split("=")[1],
      };
    }
    case "oracle": {
      const match = jdbcUrl.match(/jdbc:oracle:thin:@\/?\/?([\w.-]+):(\d+)[/:](\S+)/);
      if (!match) {
        return undefined;
      }
      return {
        host: match[1],
        port: parseInt(match[2], 10),
        database: match[3],
      };
    }
    default:
      return undefined;
  }
};

const sqlServerMajorToYear: Record<number, string> = {
  17: "2025",
  16: "2022",
  15: "2019",
};

const dockerConfigs: Record<Exclude<DatabaseType, "sqlite">, DockerConfig> = {
  postgresql: {
    resolveImage: (v) => (v ? `postgres:${v}` : "postgres"),
    defaultPort: 5432,
    user: "flyway_build",
    password: "flyway_build",
    database: "flyway_build",
    containerEnv: {
      POSTGRES_USER: "flyway_build",
      POSTGRES_PASSWORD: "flyway_build",
      POSTGRES_DB: "flyway_build",
    },
    healthCmd: "pg_isready -U flyway_build",
    buildJdbcUrl: (host, port, database) => `jdbc:postgresql://${host}:${port}/${database}`,
  },
  mysql: {
    resolveImage: (v) => (v ? `mysql:${v}` : "mysql"),
    defaultPort: 3306,
    user: "flyway_build",
    password: "flyway_build",
    database: "flyway_build",
    containerEnv: {
      MYSQL_ROOT_PASSWORD: "flyway_build",
      MYSQL_DATABASE: "flyway_build",
      MYSQL_USER: "flyway_build",
      MYSQL_PASSWORD: "flyway_build",
    },
    healthCmd: "mysqladmin ping -h localhost -u root --password=flyway_build --silent",
    buildJdbcUrl: (host, port, database) => `jdbc:mysql://${host}:${port}/${database}`,
  },
  sqlserver: {
    resolveImage: (v) => {
      if (!v) {
        return "mcr.microsoft.com/mssql/server";
      }
      const major = parseInt(v, 10);
      const year = sqlServerMajorToYear[major] ?? "2022";
      return `mcr.microsoft.com/mssql/server:${year}-latest`;
    },
    defaultPort: 1433,
    user: "sa",
    password: "Flyway_Build_1",
    database: "master",
    containerEnv: {
      ACCEPT_EULA: "Y",
      SA_PASSWORD: "Flyway_Build_1",
    },
    healthCmd:
      "(/opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P Flyway_Build_1 -Q 'SELECT 1' -C -b 2>/dev/null || /opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P Flyway_Build_1 -Q 'SELECT 1' -b 2>/dev/null)",
    buildJdbcUrl: (host, port) => `jdbc:sqlserver://${host}:${port};encrypt=false;trustServerCertificate=true`,
  },
  oracle: {
    resolveImage: (v) => {
      if (!v) {
        return "gvenzl/oracle-xe";
      }
      const major = parseInt(v, 10);
      if (major >= 23) {
        return `gvenzl/oracle-free:${major}`;
      }
      return `gvenzl/oracle-xe:${major}`;
    },
    defaultPort: 1521,
    user: "system",
    password: "test",
    database: "xepdb1",
    containerEnv: {
      ORACLE_PASSWORD: "test",
    },
    healthCmd: "healthcheck.sh",
    buildJdbcUrl: (host, port, database) => `jdbc:oracle:thin:@${host}:${port}/${database}`,
  },
};

const getDockerConfig = (type: Exclude<DatabaseType, "sqlite">): DockerConfig => dockerConfigs[type];

const probeTargetVersion = (
  dbType: Exclude<DatabaseType, "sqlite">,
  conn: JdbcConnectionInfo,
  user?: string,
  password?: string,
): string | undefined => {
  try {
    switch (dbType) {
      case "postgresql": {
        const result = execSync(
          `psql -h "${conn.host}" -p ${conn.port} -U "${user}" -d "${conn.database ?? "postgres"}" -t -A -c "SHOW server_version;"`,
          {
            encoding: "utf-8",
            env: { ...process.env, PGPASSWORD: password ?? "" },
            stdio: "pipe",
            timeout: 10000,
          },
        ).trim();
        return result.split(".")[0];
      }
      case "mysql": {
        const result = execSync(`mysql -h "${conn.host}" -P ${conn.port} -u "${user}" -N -B -e "SELECT VERSION();"`, {
          encoding: "utf-8",
          env: { ...process.env, MYSQL_PWD: password ?? "" },
          stdio: "pipe",
          timeout: 10000,
        }).trim();
        const parts = result.split(".");
        return `${parts[0]}.${parts[1]}`;
      }
      case "sqlserver": {
        const result = execSync(
          `docker run --rm --network host mcr.microsoft.com/mssql-tools /opt/mssql-tools/bin/sqlcmd` +
            ` -S "${conn.host},${conn.port}" -U "${user}" -P "${password}"` +
            ` -Q "SET NOCOUNT ON; SELECT SERVERPROPERTY('ProductVersion')" -h -1 -W`,
          { encoding: "utf-8", stdio: "pipe", timeout: 30000 },
        ).trim();
        const lines = result.split("\n").filter((l) => l.trim().length > 0);
        const versionLine = lines[lines.length - 1].trim();
        return versionLine.split(".")[0];
      }
      case "oracle":
        return undefined;
    }
  } catch {
    return undefined;
  }
};

export { getDockerConfig, parseDatabaseType, parseJdbcUrl, probeTargetVersion };
export type { DatabaseType, DockerConfig, JdbcConnectionInfo };
