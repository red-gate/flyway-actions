import { execSync as a } from "node:child_process";
import * as m from "node:fs";
import * as y from "node:os";
import * as f from "node:path";
const b = [
  { prefix: "jdbc:postgresql://", type: "postgresql" },
  { prefix: "jdbc:sqlserver://", type: "sqlserver" },
  { prefix: "jdbc:mysql://", type: "mysql" },
  { prefix: "jdbc:oracle:", type: "oracle" },
  { prefix: "jdbc:sqlite:", type: "sqlite" }
], d = (e) => b.find((t) => e.startsWith(t.prefix))?.type, h = (e) => {
  const t = d(e);
  switch (t) {
    case "postgresql":
    case "mysql": {
      const r = t === "postgresql" ? "jdbc:postgresql://" : "jdbc:mysql://", s = new URL(e.replace(r, "http://")), o = t === "postgresql" ? 5432 : 3306;
      return {
        host: s.hostname,
        port: s.port ? parseInt(s.port, 10) : o,
        database: s.pathname.slice(1) || void 0
      };
    }
    case "sqlserver": {
      const r = e.replace("jdbc:sqlserver://", ""), s = r.split(";")[0], [o, l] = s.split(":"), c = (r.includes(";") ? r.substring(r.indexOf(";") + 1) : "").split(";").find((n) => n.toLowerCase().startsWith("databasename="));
      return {
        host: o,
        port: l ? parseInt(l, 10) : 1433,
        database: c?.split("=")[1]
      };
    }
    case "oracle": {
      const r = e.match(/jdbc:oracle:thin:@\/?\/?([\w.-]+):(\d+)[/:](\S+)/);
      return r ? {
        host: r[1],
        port: parseInt(r[2], 10),
        database: r[3]
      } : void 0;
    }
    default:
      return;
  }
}, S = {
  17: "2025",
  16: "2022",
  15: "2019"
}, v = {
  postgresql: {
    resolveImage: (e) => e ? `postgres:${e}` : "postgres",
    defaultPort: 5432,
    user: "flyway_build",
    password: "flyway_build",
    database: "flyway_build",
    containerEnv: {
      POSTGRES_USER: "flyway_build",
      POSTGRES_PASSWORD: "flyway_build",
      POSTGRES_DB: "flyway_build"
    },
    healthCmd: "pg_isready -U flyway_build",
    buildJdbcUrl: (e, t, r) => `jdbc:postgresql://${e}:${t}/${r}`
  },
  mysql: {
    resolveImage: (e) => e ? `mysql:${e}` : "mysql",
    defaultPort: 3306,
    user: "flyway_build",
    password: "flyway_build",
    database: "flyway_build",
    containerEnv: {
      MYSQL_ROOT_PASSWORD: "flyway_build",
      MYSQL_DATABASE: "flyway_build",
      MYSQL_USER: "flyway_build",
      MYSQL_PASSWORD: "flyway_build"
    },
    healthCmd: "mysqladmin ping -h localhost -u root --password=flyway_build --silent",
    buildJdbcUrl: (e, t, r) => `jdbc:mysql://${e}:${t}/${r}`
  },
  sqlserver: {
    resolveImage: (e) => {
      if (!e)
        return "mcr.microsoft.com/mssql/server";
      const t = parseInt(e, 10);
      return `mcr.microsoft.com/mssql/server:${S[t] ?? "2022"}-latest`;
    },
    defaultPort: 1433,
    user: "sa",
    password: "Flyway_Build_1",
    database: "master",
    containerEnv: {
      ACCEPT_EULA: "Y",
      SA_PASSWORD: "Flyway_Build_1"
    },
    healthCmd: "(/opt/mssql-tools18/bin/sqlcmd -S localhost -U sa -P Flyway_Build_1 -Q 'SELECT 1' -C -b 2>/dev/null || /opt/mssql-tools/bin/sqlcmd -S localhost -U sa -P Flyway_Build_1 -Q 'SELECT 1' -b 2>/dev/null)",
    buildJdbcUrl: (e, t) => `jdbc:sqlserver://${e}:${t};encrypt=false;trustServerCertificate=true`
  },
  oracle: {
    resolveImage: (e) => {
      if (!e)
        return "gvenzl/oracle-xe";
      const t = parseInt(e, 10);
      return t >= 23 ? `gvenzl/oracle-free:${t}` : `gvenzl/oracle-xe:${t}`;
    },
    defaultPort: 1521,
    user: "system",
    password: "test",
    database: "xepdb1",
    containerEnv: {
      ORACLE_PASSWORD: "test"
    },
    healthCmd: "healthcheck.sh",
    buildJdbcUrl: (e, t, r) => `jdbc:oracle:thin:@${e}:${t}/${r}`
  }
}, $ = (e) => v[e], q = (e, t, r, s) => {
  try {
    switch (e) {
      case "postgresql":
        return a(
          `psql -h "${t.host}" -p ${t.port} -U "${r}" -d "${t.database ?? "postgres"}" -t -A -c "SHOW server_version;"`,
          {
            encoding: "utf-8",
            env: { ...process.env, PGPASSWORD: s ?? "" },
            stdio: "pipe",
            timeout: 1e4
          }
        ).trim().split(".")[0];
      case "mysql": {
        const l = a(`mysql -h "${t.host}" -P ${t.port} -u "${r}" -N -B -e "SELECT VERSION();"`, {
          encoding: "utf-8",
          env: { ...process.env, MYSQL_PWD: s ?? "" },
          stdio: "pipe",
          timeout: 1e4
        }).trim().split(".");
        return `${l[0]}.${l[1]}`;
      }
      case "sqlserver": {
        const l = a(
          `docker run --rm --network host mcr.microsoft.com/mssql-tools /opt/mssql-tools/bin/sqlcmd -S "${t.host},${t.port}" -U "${r}" -P "${s}" -Q "SET NOCOUNT ON; SELECT SERVERPROPERTY('ProductVersion')" -h -1 -W`,
          { encoding: "utf-8", stdio: "pipe", timeout: 3e4 }
        ).trim().split(`
`).filter((c) => c.trim().length > 0);
        return l[l.length - 1].trim().split(".")[0];
      }
      case "oracle":
        return;
    }
  } catch {
    return;
  }
}, _ = () => {
  const e = f.join(y.tmpdir(), `flyway_build_${Date.now()}.db`);
  return {
    jdbcUrl: `jdbc:sqlite:${e}`,
    user: "",
    password: "",
    cleanup: () => (m.rmSync(e, { force: !0 }), Promise.resolve())
  };
}, w = (e, t, r, s) => {
  const o = Object.entries(r).map(([l, i]) => `-e ${l}=${i}`).join(" ");
  return `docker run -d --name ${e} -P --health-cmd="${s}" --health-interval=2s --health-timeout=5s --health-retries=60 ${o} ${t}`;
}, g = (e, t = 120) => {
  for (let r = 0; r < t; r++) {
    const s = a(`docker inspect --format={{.State.Health.Status}} ${e}`, {
      stdio: "pipe",
      encoding: "utf-8"
    }).trim();
    if (s === "healthy")
      return;
    if (s === "unhealthy")
      throw a(`docker rm -f ${e}`, { stdio: "pipe" }), new Error("Container became unhealthy");
    if (r === t - 1)
      throw a(`docker rm -f ${e}`, { stdio: "pipe" }), new Error("Container did not become healthy in time");
    a("sleep 1", { stdio: "pipe" });
  }
}, P = (e, t) => {
  const r = a(`docker port ${e} ${t}`, {
    stdio: "pipe",
    encoding: "utf-8"
  }).trim();
  return parseInt(r.split(":").pop(), 10);
}, E = (e, t, r, s) => {
  const o = $(e), l = h(t);
  let i;
  l && (i = q(e, l, r, s));
  const c = o.resolveImage(i), n = `flyway_build_${Date.now()}`, p = w(n, c, o.containerEnv, o.healthCmd);
  a(p, { stdio: "pipe" }), g(n);
  const u = P(n, o.defaultPort);
  return {
    jdbcUrl: o.buildJdbcUrl("localhost", u, o.database),
    user: o.user,
    password: o.password,
    cleanup: () => (a(`docker rm -f ${n}`, { stdio: "pipe" }), Promise.resolve())
  };
}, O = (e, t, r) => {
  const s = d(e);
  if (s)
    return s === "sqlite" ? _() : E(s, e, t, r);
};
export {
  O as provisionBuildDatabase
};
