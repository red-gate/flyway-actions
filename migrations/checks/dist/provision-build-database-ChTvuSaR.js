import * as l from "node:fs";
import * as c from "node:os";
import * as p from "node:path";
import { i as r, w as i, s as u } from "./main-DXfcowYv.js";
const b = [
  { prefix: "jdbc:postgresql://", type: "postgresql" },
  { prefix: "jdbc:sqlserver://", type: "sqlserver" },
  { prefix: "jdbc:mysql://", type: "mysql" },
  { prefix: "jdbc:oracle:", type: "oracle" },
  { prefix: "jdbc:sqlite:", type: "sqlite" }
], f = (e) => b.find((s) => e.startsWith(s.prefix))?.type, w = {
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
}, o = (e) => w[e], g = async () => {
  const { PostgreSqlContainer: e } = await import("@testcontainers/postgresql"), s = o("postgresql"), t = await new e(s.image).withDatabase("flyway_build").withUsername("test").withPassword("test").start();
  return {
    host: t.getHost(),
    port: t.getPort(),
    database: t.getDatabase(),
    user: t.getUsername(),
    password: t.getPassword(),
    stop: () => t.stop()
  };
}, m = async () => {
  const { MSSQLServerContainer: e } = await import("@testcontainers/mssqlserver"), s = o("sqlserver"), t = await new e(s.image).acceptLicense().start();
  return {
    host: t.getHost(),
    port: t.getPort(),
    database: t.getDatabase(),
    user: t.getUsername(),
    password: t.getPassword(),
    stop: () => t.stop()
  };
}, y = async () => {
  const { MySqlContainer: e } = await import("@testcontainers/mysql"), s = o("mysql"), t = await new e(s.image).withDatabase("flyway_build").withUsername("test").withUserPassword("test").start();
  return {
    host: t.getHost(),
    port: t.getPort(),
    database: t.getDatabase(),
    user: t.getUsername(),
    password: t.getUserPassword(),
    stop: () => t.stop()
  };
}, q = async () => {
  const { GenericContainer: e, Wait: s } = await import("testcontainers"), t = o("oracle"), a = await new e(t.image).withExposedPorts(t.defaultPort).withEnvironment({
    ORACLE_PASSWORD: t.defaultPassword
  }).withWaitStrategy(s.forHealthCheck()).start();
  return {
    host: a.getHost(),
    port: a.getMappedPort(t.defaultPort),
    database: t.defaultDatabase,
    user: t.defaultUser,
    password: t.defaultPassword,
    stop: () => a.stop()
  };
}, P = {
  postgresql: g,
  sqlserver: m,
  mysql: y,
  oracle: q
}, v = (e) => {
  const s = p.join(c.tmpdir(), `flyway_build_${Date.now()}.db`), t = `jdbc:sqlite:${s}`;
  return r(`Auto-provisioning SQLite build database at ${s} (target: ${e})`), {
    jdbcUrl: t,
    user: "",
    password: "",
    cleanup: () => {
      try {
        l.rmSync(s, { force: !0 }), r("SQLite build database removed");
      } catch (a) {
        i(`Failed to remove SQLite build database: ${a}`);
      }
      return Promise.resolve();
    }
  };
}, h = async (e) => {
  r(`Auto-provisioning ${e} build database via Docker...`);
  const s = P[e], t = await s(), n = o(e).buildJdbcUrl(t.host, t.port, t.database);
  return u(t.password), r(`Build database provisioned at ${t.host}:${t.port}`), {
    jdbcUrl: n,
    user: t.user,
    password: t.password,
    cleanup: async () => {
      try {
        await t.stop(), r("Build database container stopped");
      } catch (d) {
        i(`Failed to stop build database container: ${d}`);
      }
    }
  };
}, U = async (e) => {
  const s = f(e);
  if (!s) {
    r(`Auto-provisioning not available for database URL: ${e}`);
    return;
  }
  return s === "sqlite" ? v(e) : h(s);
};
export {
  U as provisionBuildDatabase
};
