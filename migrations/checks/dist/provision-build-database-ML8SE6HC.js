import { execSync as o } from "node:child_process";
import * as p from "node:fs";
import * as u from "node:os";
import * as b from "node:path";
const f = [
  { prefix: "jdbc:postgresql://", type: "postgresql" },
  { prefix: "jdbc:sqlserver://", type: "sqlserver" },
  { prefix: "jdbc:mysql://", type: "mysql" },
  { prefix: "jdbc:oracle:", type: "oracle" },
  { prefix: "jdbc:sqlite:", type: "sqlite" }
], n = (e) => f.find((r) => e.startsWith(r.prefix))?.type, m = {
  image: "gvenzl/oracle-xe",
  defaultUser: "system",
  defaultPassword: "test",
  defaultPort: 1521,
  defaultDatabase: "xepdb1",
  buildJdbcUrl: (e, r, t) => `jdbc:oracle:thin:@${e}:${r}/${t}`
}, y = (e) => {
  switch (n(e)) {
    case "postgresql": {
      const t = new URL(e.replace("jdbc:postgresql://", "http://"));
      return t.pathname = "/flyway_build", `jdbc:postgresql://${t.host}/flyway_build`;
    }
    case "mysql": {
      const t = new URL(e.replace("jdbc:mysql://", "http://"));
      return t.pathname = "/flyway_build", `jdbc:mysql://${t.host}/flyway_build`;
    }
    case "sqlserver": {
      const t = e.replace("jdbc:sqlserver://", ""), s = t.split(";")[0], l = t.includes(";") ? t.substring(t.indexOf(";") + 1) : "", c = l.split(";").filter((a) => a.length > 0).map((a) => a.toLowerCase().startsWith("databasename=") ? "databaseName=flyway_build" : a).join(";"), i = l.split(";").some((a) => a.toLowerCase().startsWith("databasename=")) ? c : `databaseName=flyway_build;${c}`;
      return `jdbc:sqlserver://${s};${i}`.replace(/;$/, "");
    }
    default:
      return;
  }
}, h = () => m, w = () => {
  const e = b.join(u.tmpdir(), `flyway_build_${Date.now()}.db`);
  return {
    jdbcUrl: `jdbc:sqlite:${e}`,
    user: "",
    password: "",
    cleanup: () => (p.rmSync(e, { force: !0 }), Promise.resolve())
  };
}, q = (e, r, t) => {
  const s = y(e);
  if (s)
    return {
      jdbcUrl: s,
      user: r ?? "",
      password: t ?? "",
      provisioner: "create-database",
      cleanup: () => Promise.resolve()
    };
}, j = () => {
  const e = h(), t = `flyway_build_${Date.now()}`;
  o(`docker run -d --name ${t} -P -e ORACLE_PASSWORD=${e.defaultPassword} ${e.image}`, {
    stdio: "pipe"
  });
  const s = 120;
  for (let i = 0; i < s && o(`docker inspect --format={{.State.Health.Status}} ${t}`, {
    stdio: "pipe",
    encoding: "utf-8"
  }).trim() !== "healthy"; i++) {
    if (i === s - 1)
      throw o(`docker rm -f ${t}`, { stdio: "pipe" }), new Error("Oracle container did not become healthy in time");
    o("sleep 1", { stdio: "pipe" });
  }
  const c = o(`docker port ${t} ${e.defaultPort}`, {
    stdio: "pipe",
    encoding: "utf-8"
  }).trim().split(":").pop();
  return {
    jdbcUrl: e.buildJdbcUrl("localhost", parseInt(c, 10), e.defaultDatabase),
    user: e.defaultUser,
    password: e.defaultPassword,
    cleanup: () => (o(`docker rm -f ${t}`, { stdio: "pipe" }), Promise.resolve())
  };
}, v = (e, r, t) => {
  const s = n(e);
  if (s)
    switch (s) {
      case "sqlite":
        return w();
      case "postgresql":
      case "mysql":
      case "sqlserver":
        return q(e, r, t);
      case "oracle":
        return j();
    }
};
export {
  v as provisionBuildDatabase
};
