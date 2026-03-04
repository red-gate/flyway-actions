type DatabaseType = "postgresql" | "sqlserver" | "mysql" | "oracle";

type DatabaseConfig = {
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
];

const embeddedPrefixes = ["jdbc:sqlite:", "jdbc:h2:"];

const parseDatabaseType = (jdbcUrl: string): DatabaseType | undefined => {
  if (embeddedPrefixes.some((p) => jdbcUrl.startsWith(p))) {
    return undefined;
  }
  return jdbcPrefixMap.find((entry) => jdbcUrl.startsWith(entry.prefix))?.type;
};

const databaseConfigs: Record<DatabaseType, DatabaseConfig> = {
  postgresql: {
    image: "postgres",
    defaultUser: "test",
    defaultPassword: "test",
    defaultPort: 5432,
    defaultDatabase: "flyway_build",
    buildJdbcUrl: (host, port, database) => `jdbc:postgresql://${host}:${port}/${database}`,
  },
  sqlserver: {
    image: "mcr.microsoft.com/mssql/server",
    defaultUser: "sa",
    defaultPassword: "Flyway_Build_1",
    defaultPort: 1433,
    defaultDatabase: "master",
    buildJdbcUrl: (host, port) => `jdbc:sqlserver://${host}:${port};encrypt=false;trustServerCertificate=true`,
  },
  mysql: {
    image: "mysql",
    defaultUser: "test",
    defaultPassword: "test",
    defaultPort: 3306,
    defaultDatabase: "flyway_build",
    buildJdbcUrl: (host, port, database) => `jdbc:mysql://${host}:${port}/${database}`,
  },
  oracle: {
    image: "gvenzl/oracle-xe",
    defaultUser: "system",
    defaultPassword: "test",
    defaultPort: 1521,
    defaultDatabase: "xepdb1",
    buildJdbcUrl: (host, port, database) => `jdbc:oracle:thin:@${host}:${port}/${database}`,
  },
};

const getDatabaseConfig = (type: DatabaseType): DatabaseConfig => databaseConfigs[type];

export { getDatabaseConfig, parseDatabaseType };
export type { DatabaseConfig, DatabaseType };
