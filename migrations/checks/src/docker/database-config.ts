type DatabaseType = "postgresql" | "sqlserver" | "mysql" | "oracle" | "sqlite";

type OracleDockerConfig = {
  image: string;
  defaultUser: string;
  defaultPassword: string;
  defaultPort: number;
  defaultDatabase: string;
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

const oracleDockerConfig: OracleDockerConfig = {
  image: "gvenzl/oracle-xe",
  defaultUser: "system",
  defaultPassword: "test",
  defaultPort: 1521,
  defaultDatabase: "xepdb1",
  buildJdbcUrl: (host, port, database) => `jdbc:oracle:thin:@${host}:${port}/${database}`,
};

const constructBuildUrl = (targetUrl: string): string | undefined => {
  const dbType = parseDatabaseType(targetUrl);

  switch (dbType) {
    case "postgresql": {
      const url = new URL(targetUrl.replace("jdbc:postgresql://", "http://"));
      url.pathname = "/flyway_build";
      return `jdbc:postgresql://${url.host}/flyway_build`;
    }
    case "mysql": {
      const url = new URL(targetUrl.replace("jdbc:mysql://", "http://"));
      url.pathname = "/flyway_build";
      return `jdbc:mysql://${url.host}/flyway_build`;
    }
    case "sqlserver": {
      const afterPrefix = targetUrl.replace("jdbc:sqlserver://", "");
      const hostPort = afterPrefix.split(";")[0];
      const params = afterPrefix.includes(";") ? afterPrefix.substring(afterPrefix.indexOf(";") + 1) : "";
      const updatedParams = params
        .split(";")
        .filter((p) => p.length > 0)
        .map((p) => (p.toLowerCase().startsWith("databasename=") ? "databaseName=flyway_build" : p))
        .join(";");
      const hasDatabaseName = params.split(";").some((p) => p.toLowerCase().startsWith("databasename="));
      const finalParams = hasDatabaseName ? updatedParams : `databaseName=flyway_build;${updatedParams}`;
      return `jdbc:sqlserver://${hostPort};${finalParams}`.replace(/;$/, "");
    }
    default:
      return undefined;
  }
};

const getOracleDockerConfig = (): OracleDockerConfig => oracleDockerConfig;

export { constructBuildUrl, getOracleDockerConfig, parseDatabaseType };
export type { DatabaseType, OracleDockerConfig };
