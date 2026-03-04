import { getDatabaseConfig, parseDatabaseType } from "../../src/docker/database-config.js";

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

describe("getDatabaseConfig", () => {
  it("should return postgresql config with correct image", () => {
    const config = getDatabaseConfig("postgresql");

    expect(config.image).toBe("postgres");
    expect(config.defaultPort).toBe(5432);
  });

  it("should return sqlserver config with correct image", () => {
    const config = getDatabaseConfig("sqlserver");

    expect(config.image).toBe("mcr.microsoft.com/mssql/server");
    expect(config.defaultPort).toBe(1433);
  });

  it("should return mysql config with correct image", () => {
    const config = getDatabaseConfig("mysql");

    expect(config.image).toBe("mysql");
    expect(config.defaultPort).toBe(3306);
  });

  it("should return oracle config with correct image", () => {
    const config = getDatabaseConfig("oracle");

    expect(config.image).toBe("gvenzl/oracle-xe");
    expect(config.defaultPort).toBe(1521);
  });

  it("should build correct postgresql JDBC URL", () => {
    const config = getDatabaseConfig("postgresql");

    expect(config.buildJdbcUrl("localhost", 5432, "flyway_build")).toBe(
      "jdbc:postgresql://localhost:5432/flyway_build",
    );
  });

  it("should build correct sqlserver JDBC URL", () => {
    const config = getDatabaseConfig("sqlserver");

    expect(config.buildJdbcUrl("localhost", 1433, "master")).toBe(
      "jdbc:sqlserver://localhost:1433;encrypt=false;trustServerCertificate=true",
    );
  });

  it("should build correct mysql JDBC URL", () => {
    const config = getDatabaseConfig("mysql");

    expect(config.buildJdbcUrl("localhost", 3306, "flyway_build")).toBe("jdbc:mysql://localhost:3306/flyway_build");
  });

  it("should build correct oracle JDBC URL", () => {
    const config = getDatabaseConfig("oracle");

    expect(config.buildJdbcUrl("localhost", 1521, "xepdb1")).toBe("jdbc:oracle:thin:@localhost:1521/xepdb1");
  });

  it("should build correct sqlite JDBC URL", () => {
    const config = getDatabaseConfig("sqlite");

    expect(config.buildJdbcUrl("", 0, "flyway_build")).toBe("jdbc:sqlite:flyway_build");
  });
});
