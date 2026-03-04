import * as o from "node:fs";
import * as i from "node:os";
import * as n from "node:path";
const l = [
  { prefix: "jdbc:postgresql://", type: "postgresql" },
  { prefix: "jdbc:sqlserver://", type: "sqlserver" },
  { prefix: "jdbc:mysql://", type: "mysql" },
  { prefix: "jdbc:oracle:", type: "oracle" },
  { prefix: "jdbc:sqlite:", type: "sqlite" }
], d = (e) => l.find((s) => e.startsWith(s.prefix))?.type, c = {
  sqlite: {
    image: "",
    defaultUser: "",
    defaultPassword: "",
    defaultPort: 0,
    defaultDatabase: "flyway_build",
    buildJdbcUrl: (e, s, t) => `jdbc:sqlite:${t}`
  },
  postgresql: {
    image: "postgres",
    defaultUser: "test",
    defaultPassword: "test",
    defaultPort: 5432,
    defaultDatabase: "flyway_build",
    buildJdbcUrl: (e, s, t) => `jdbc:postgresql://${e}:${s}/${t}`
  },
  sqlserver: {
    image: "mcr.microsoft.com/mssql/server",
    defaultUser: "sa",
    defaultPassword: "Flyway_Build_1",
    defaultPort: 1433,
    defaultDatabase: "master",
    buildJdbcUrl: (e, s) => `jdbc:sqlserver://${e}:${s};encrypt=false;trustServerCertificate=true`
  },
  mysql: {
    image: "mysql",
    defaultUser: "test",
    defaultPassword: "test",
    defaultPort: 3306,
    defaultDatabase: "flyway_build",
    buildJdbcUrl: (e, s, t) => `jdbc:mysql://${e}:${s}/${t}`
  },
  oracle: {
    image: "gvenzl/oracle-xe",
    defaultUser: "system",
    defaultPassword: "test",
    defaultPort: 1521,
    defaultDatabase: "xepdb1",
    buildJdbcUrl: (e, s, t) => `jdbc:oracle:thin:@${e}:${s}/${t}`
  }
}, a = (e) => c[e], p = async () => {
  const { PostgreSqlContainer: e } = await import("@testcontainers/postgresql"), s = a("postgresql"), t = await new e(s.image).withDatabase("flyway_build").withUsername("test").withPassword("test").start();
  return {
    host: t.getHost(),
    port: t.getPort(),
    database: t.getDatabase(),
    user: t.getUsername(),
    password: t.getPassword(),
    stop: () => t.stop()
  };
}, u = async () => {
  const { MSSQLServerContainer: e } = await import("@testcontainers/mssqlserver"), s = a("sqlserver"), t = await new e(s.image).acceptLicense().start();
  return {
    host: t.getHost(),
    port: t.getPort(),
    database: t.getDatabase(),
    user: t.getUsername(),
    password: t.getPassword(),
    stop: () => t.stop()
  };
}, f = async () => {
  const { MySqlContainer: e } = await import("@testcontainers/mysql"), s = a("mysql"), t = await new e(s.image).withDatabase("flyway_build").withUsername("test").withUserPassword("test").start();
  return {
    host: t.getHost(),
    port: t.getPort(),
    database: t.getDatabase(),
    user: t.getUsername(),
    password: t.getUserPassword(),
    stop: () => t.stop()
  };
}, b = async () => {
  const { GenericContainer: e, Wait: s } = await import("testcontainers"), t = a("oracle"), r = await new e(t.image).withExposedPorts(t.defaultPort).withEnvironment({
    ORACLE_PASSWORD: t.defaultPassword
  }).withWaitStrategy(s.forHealthCheck()).start();
  return {
    host: r.getHost(),
    port: r.getMappedPort(t.defaultPort),
    database: t.defaultDatabase,
    user: t.defaultUser,
    password: t.defaultPassword,
    stop: () => r.stop()
  };
}, w = {
  postgresql: p,
  sqlserver: u,
  mysql: f,
  oracle: b
}, g = () => {
  const e = n.join(i.tmpdir(), `flyway_build_${Date.now()}.db`);
  return {
    jdbcUrl: `jdbc:sqlite:${e}`,
    user: "",
    password: "",
    cleanup: () => (o.rmSync(e, { force: !0 }), Promise.resolve())
  };
}, m = async (e) => {
  const s = w[e], t = await s();
  return {
    jdbcUrl: a(e).buildJdbcUrl(t.host, t.port, t.database),
    user: t.user,
    password: t.password,
    cleanup: async () => {
      await t.stop();
    }
  };
}, q = async (e) => {
  const s = d(e);
  if (s)
    return s === "sqlite" ? g() : m(s);
};
export {
  q as provisionBuildDatabase
};
