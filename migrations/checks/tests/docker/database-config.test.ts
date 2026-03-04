import { constructBuildUrl, getOracleDockerConfig, parseDatabaseType } from "../../src/docker/database-config.js";

describe("parseDatabaseType", () => {
  it("should return postgresql for jdbc:postgresql:// prefix", () => {
    expect(parseDatabaseType("jdbc:postgresql://localhost:5432/mydb")).toBe("postgresql");
  });

  it("should return sqlserver for jdbc:sqlserver:// prefix", () => {
    expect(parseDatabaseType("jdbc:sqlserver://localhost:1433;databaseName=mydb")).toBe("sqlserver");
  });

  it("should return mysql for jdbc:mysql:// prefix", () => {
    expect(parseDatabaseType("jdbc:mysql://localhost:3306/mydb")).toBe("mysql");
  });

  it("should return oracle for jdbc:oracle: prefix", () => {
    expect(parseDatabaseType("jdbc:oracle:thin:@localhost:1521/xepdb1")).toBe("oracle");
  });

  it("should return sqlite for jdbc:sqlite: prefix", () => {
    expect(parseDatabaseType("jdbc:sqlite:mydb.db")).toBe("sqlite");
  });

  it("should return undefined for jdbc:h2: prefix", () => {
    expect(parseDatabaseType("jdbc:h2:mem:testdb")).toBeUndefined();
  });

  it("should return undefined for unknown JDBC prefix", () => {
    expect(parseDatabaseType("jdbc:unknown://localhost/db")).toBeUndefined();
  });
});

describe("constructBuildUrl", () => {
  it("should construct postgresql build URL", () => {
    expect(constructBuildUrl("jdbc:postgresql://dbhost:5432/mydb")).toBe("jdbc:postgresql://dbhost:5432/flyway_build");
  });

  it("should construct postgresql build URL with default port", () => {
    expect(constructBuildUrl("jdbc:postgresql://dbhost/mydb")).toBe("jdbc:postgresql://dbhost/flyway_build");
  });

  it("should construct mysql build URL", () => {
    expect(constructBuildUrl("jdbc:mysql://dbhost:3306/mydb")).toBe("jdbc:mysql://dbhost:3306/flyway_build");
  });

  it("should construct sqlserver build URL replacing databaseName", () => {
    expect(constructBuildUrl("jdbc:sqlserver://dbhost:1433;databaseName=mydb")).toBe(
      "jdbc:sqlserver://dbhost:1433;databaseName=flyway_build",
    );
  });

  it("should construct sqlserver build URL preserving other params", () => {
    expect(constructBuildUrl("jdbc:sqlserver://dbhost:1433;databaseName=mydb;encrypt=false")).toBe(
      "jdbc:sqlserver://dbhost:1433;databaseName=flyway_build;encrypt=false",
    );
  });

  it("should construct sqlserver build URL adding databaseName when missing", () => {
    expect(constructBuildUrl("jdbc:sqlserver://dbhost:1433;encrypt=false")).toBe(
      "jdbc:sqlserver://dbhost:1433;databaseName=flyway_build;encrypt=false",
    );
  });

  it("should return undefined for oracle", () => {
    expect(constructBuildUrl("jdbc:oracle:thin:@localhost:1521/xepdb1")).toBeUndefined();
  });

  it("should return undefined for sqlite", () => {
    expect(constructBuildUrl("jdbc:sqlite:mydb.db")).toBeUndefined();
  });

  it("should return undefined for unknown JDBC URL", () => {
    expect(constructBuildUrl("jdbc:unknown://localhost/db")).toBeUndefined();
  });
});

describe("getOracleDockerConfig", () => {
  it("should return oracle config with correct image", () => {
    const config = getOracleDockerConfig();

    expect(config.image).toBe("gvenzl/oracle-xe");
    expect(config.defaultPort).toBe(1521);
  });

  it("should build correct oracle JDBC URL", () => {
    const config = getOracleDockerConfig();

    expect(config.buildJdbcUrl("localhost", 1521, "xepdb1")).toBe("jdbc:oracle:thin:@localhost:1521/xepdb1");
  });
});
