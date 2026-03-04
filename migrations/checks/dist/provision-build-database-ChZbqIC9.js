import { i as o, s as d, w as l } from "./main-D9ghw_-J.js";
const c = [
  { prefix: "jdbc:postgresql://", type: "postgresql" },
  { prefix: "jdbc:sqlserver://", type: "sqlserver" },
  { prefix: "jdbc:mysql://", type: "mysql" },
  { prefix: "jdbc:oracle:", type: "oracle" }
], p = ["jdbc:sqlite:", "jdbc:h2:"], u = (s) => {
  if (!p.some((e) => s.startsWith(e)))
    return c.find((e) => s.startsWith(e.prefix))?.type;
}, b = {
  postgresql: {
    image: "postgres",
    defaultUser: "test",
    defaultPassword: "test",
    defaultPort: 5432,
    defaultDatabase: "flyway_build",
    buildJdbcUrl: (s, e, t) => `jdbc:postgresql://${s}:${e}/${t}`
  },
  sqlserver: {
    image: "mcr.microsoft.com/mssql/server",
    defaultUser: "sa",
    defaultPassword: "Flyway_Build_1",
    defaultPort: 1433,
    defaultDatabase: "master",
    buildJdbcUrl: (s, e) => `jdbc:sqlserver://${s}:${e};encrypt=false;trustServerCertificate=true`
  },
  mysql: {
    image: "mysql",
    defaultUser: "test",
    defaultPassword: "test",
    defaultPort: 3306,
    defaultDatabase: "flyway_build",
    buildJdbcUrl: (s, e, t) => `jdbc:mysql://${s}:${e}/${t}`
  },
  oracle: {
    image: "gvenzl/oracle-xe",
    defaultUser: "system",
    defaultPassword: "test",
    defaultPort: 1521,
    defaultDatabase: "xepdb1",
    buildJdbcUrl: (s, e, t) => `jdbc:oracle:thin:@${s}:${e}/${t}`
  }
}, r = (s) => b[s], f = async () => {
  const { PostgreSqlContainer: s } = await import("@testcontainers/postgresql"), e = r("postgresql"), t = await new s(e.image).withDatabase("flyway_build").withUsername("test").withPassword("test").start();
  return {
    host: t.getHost(),
    port: t.getPort(),
    database: t.getDatabase(),
    user: t.getUsername(),
    password: t.getPassword(),
    stop: () => t.stop()
  };
}, w = async () => {
  const { MSSQLServerContainer: s } = await import("@testcontainers/mssqlserver"), e = r("sqlserver"), t = await new s(e.image).acceptLicense().start();
  return {
    host: t.getHost(),
    port: t.getPort(),
    database: t.getDatabase(),
    user: t.getUsername(),
    password: t.getPassword(),
    stop: () => t.stop()
  };
}, g = async () => {
  const { MySqlContainer: s } = await import("@testcontainers/mysql"), e = r("mysql"), t = await new s(e.image).withDatabase("flyway_build").withUsername("test").withUserPassword("test").start();
  return {
    host: t.getHost(),
    port: t.getPort(),
    database: t.getDatabase(),
    user: t.getUsername(),
    password: t.getUserPassword(),
    stop: () => t.stop()
  };
}, y = async () => {
  const { GenericContainer: s, Wait: e } = await import("testcontainers"), t = r("oracle"), a = await new s(t.image).withExposedPorts(t.defaultPort).withEnvironment({
    ORACLE_PASSWORD: t.defaultPassword
  }).withWaitStrategy(e.forHealthCheck()).start();
  return {
    host: a.getHost(),
    port: a.getMappedPort(t.defaultPort),
    database: t.defaultDatabase,
    user: t.defaultUser,
    password: t.defaultPassword,
    stop: () => a.stop()
  };
}, m = {
  postgresql: f,
  sqlserver: w,
  mysql: g,
  oracle: y
}, h = async (s) => {
  const e = u(s);
  if (!e) {
    o(`Auto-provisioning not available for database URL: ${s}`);
    return;
  }
  o(`Auto-provisioning ${e} build database via Docker...`);
  const t = m[e], a = await t(), i = r(e).buildJdbcUrl(a.host, a.port, a.database);
  return d(a.password), o(`Build database provisioned at ${a.host}:${a.port}`), {
    jdbcUrl: i,
    user: a.user,
    password: a.password,
    cleanup: async () => {
      try {
        await a.stop(), o("Build database container stopped");
      } catch (n) {
        l(`Failed to stop build database container: ${n}`);
      }
    }
  };
};
export {
  h as provisionBuildDatabase
};
