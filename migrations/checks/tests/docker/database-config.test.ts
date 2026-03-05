vi.doMock("node:child_process", () => ({
  execSync: vi.fn(),
}));

const { execSync } = await import("node:child_process");
const mockedExecSync = vi.mocked(execSync);

const { getDockerConfig, parseDatabaseType, parseJdbcUrl, probeTargetVersion } =
  await import("../../src/docker/database-config.js");

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

describe("parseJdbcUrl", () => {
  it("should parse postgresql URL with port", () => {
    expect(parseJdbcUrl("jdbc:postgresql://dbhost:5432/mydb")).toEqual({
      host: "dbhost",
      port: 5432,
      database: "mydb",
    });
  });

  it("should parse postgresql URL without port", () => {
    expect(parseJdbcUrl("jdbc:postgresql://dbhost/mydb")).toEqual({
      host: "dbhost",
      port: 5432,
      database: "mydb",
    });
  });

  it("should parse mysql URL", () => {
    expect(parseJdbcUrl("jdbc:mysql://dbhost:3306/mydb")).toEqual({
      host: "dbhost",
      port: 3306,
      database: "mydb",
    });
  });

  it("should parse sqlserver URL with databaseName", () => {
    expect(parseJdbcUrl("jdbc:sqlserver://dbhost:1433;databaseName=mydb")).toEqual({
      host: "dbhost",
      port: 1433,
      database: "mydb",
    });
  });

  it("should parse sqlserver URL without databaseName", () => {
    expect(parseJdbcUrl("jdbc:sqlserver://dbhost:1433;encrypt=false")).toEqual({
      host: "dbhost",
      port: 1433,
      database: undefined,
    });
  });

  it("should parse oracle URL", () => {
    expect(parseJdbcUrl("jdbc:oracle:thin:@dbhost:1521/xepdb1")).toEqual({
      host: "dbhost",
      port: 1521,
      database: "xepdb1",
    });
  });

  it("should parse oracle URL with double-slash format", () => {
    expect(parseJdbcUrl("jdbc:oracle:thin:@//dbhost:1521/xepdb1")).toEqual({
      host: "dbhost",
      port: 1521,
      database: "xepdb1",
    });
  });

  it("should return undefined for sqlite", () => {
    expect(parseJdbcUrl("jdbc:sqlite:mydb.db")).toBeUndefined();
  });

  it("should return undefined for unknown JDBC URL", () => {
    expect(parseJdbcUrl("jdbc:unknown://localhost/db")).toBeUndefined();
  });
});

describe("getDockerConfig", () => {
  it("should return postgresql config", () => {
    const config = getDockerConfig("postgresql");

    expect(config.defaultPort).toBe(5432);
    expect(config.user).toBe("flyway_build");
    expect(config.database).toBe("flyway_build");
  });

  it("should return mysql config", () => {
    const config = getDockerConfig("mysql");

    expect(config.defaultPort).toBe(3306);
    expect(config.user).toBe("flyway_build");
    expect(config.database).toBe("flyway_build");
  });

  it("should return sqlserver config", () => {
    const config = getDockerConfig("sqlserver");

    expect(config.defaultPort).toBe(1433);
    expect(config.user).toBe("sa");
  });

  it("should return oracle config", () => {
    const config = getDockerConfig("oracle");

    expect(config.defaultPort).toBe(1521);
    expect(config.user).toBe("system");
    expect(config.database).toBe("xepdb1");
  });

  describe("resolveImage", () => {
    it("should resolve postgresql image with version", () => {
      expect(getDockerConfig("postgresql").resolveImage("16")).toBe("postgres:16");
    });

    it("should resolve postgresql image without version", () => {
      expect(getDockerConfig("postgresql").resolveImage()).toBe("postgres");
    });

    it("should resolve mysql image with version", () => {
      expect(getDockerConfig("mysql").resolveImage("8.4")).toBe("mysql:8.4");
    });

    it("should resolve sqlserver 2022 image from major version 16", () => {
      expect(getDockerConfig("sqlserver").resolveImage("16")).toBe("mcr.microsoft.com/mssql/server:2022-latest");
    });

    it("should resolve sqlserver 2019 image from major version 15", () => {
      expect(getDockerConfig("sqlserver").resolveImage("15")).toBe("mcr.microsoft.com/mssql/server:2019-latest");
    });

    it("should resolve sqlserver 2025 image from major version 17", () => {
      expect(getDockerConfig("sqlserver").resolveImage("17")).toBe("mcr.microsoft.com/mssql/server:2025-latest");
    });

    it("should fall back to 2022 for unknown sqlserver version", () => {
      expect(getDockerConfig("sqlserver").resolveImage("99")).toBe("mcr.microsoft.com/mssql/server:2022-latest");
    });

    it("should resolve oracle-xe for version 21", () => {
      expect(getDockerConfig("oracle").resolveImage("21")).toBe("gvenzl/oracle-xe:21");
    });

    it("should resolve oracle-free for version 23", () => {
      expect(getDockerConfig("oracle").resolveImage("23")).toBe("gvenzl/oracle-free:23");
    });

    it("should resolve default oracle image without version", () => {
      expect(getDockerConfig("oracle").resolveImage()).toBe("gvenzl/oracle-xe");
    });
  });

  describe("buildJdbcUrl", () => {
    it("should build postgresql JDBC URL", () => {
      expect(getDockerConfig("postgresql").buildJdbcUrl("localhost", 55432, "flyway_build")).toBe(
        "jdbc:postgresql://localhost:55432/flyway_build",
      );
    });

    it("should build mysql JDBC URL", () => {
      expect(getDockerConfig("mysql").buildJdbcUrl("localhost", 53306, "flyway_build")).toBe(
        "jdbc:mysql://localhost:53306/flyway_build",
      );
    });

    it("should build sqlserver JDBC URL", () => {
      expect(getDockerConfig("sqlserver").buildJdbcUrl("localhost", 51433, "master")).toBe(
        "jdbc:sqlserver://localhost:51433;encrypt=false;trustServerCertificate=true",
      );
    });

    it("should build oracle JDBC URL", () => {
      expect(getDockerConfig("oracle").buildJdbcUrl("localhost", 51521, "xepdb1")).toBe(
        "jdbc:oracle:thin:@localhost:51521/xepdb1",
      );
    });
  });
});

describe("probeTargetVersion", () => {
  it("should probe postgresql version", () => {
    mockedExecSync.mockReturnValueOnce("16.2");

    const version = probeTargetVersion("postgresql", { host: "dbhost", port: 5432, database: "mydb" }, "admin", "pw");

    expect(version).toBe("16");
    expect(mockedExecSync).toHaveBeenCalledWith(expect.stringContaining("psql"), expect.anything());
  });

  it("should probe mysql version", () => {
    mockedExecSync.mockReturnValueOnce("8.4.3");

    const version = probeTargetVersion("mysql", { host: "dbhost", port: 3306, database: "mydb" }, "admin", "pw");

    expect(version).toBe("8.4");
    expect(mockedExecSync).toHaveBeenCalledWith(expect.stringContaining("mysql"), expect.anything());
  });

  it("should probe sqlserver version via docker", () => {
    mockedExecSync.mockReturnValueOnce("16.0.4165.4\n");

    const version = probeTargetVersion("sqlserver", { host: "dbhost", port: 1433 }, "sa", "pw");

    expect(version).toBe("16");
    expect(mockedExecSync).toHaveBeenCalledWith(expect.stringContaining("mssql-tools"), expect.anything());
  });

  it("should return undefined for oracle", () => {
    const version = probeTargetVersion("oracle", { host: "dbhost", port: 1521, database: "xepdb1" }, "system", "pw");

    expect(version).toBeUndefined();
  });

  it("should return undefined when probe command fails", () => {
    mockedExecSync.mockImplementation(() => {
      throw new Error("connection refused");
    });

    const version = probeTargetVersion("postgresql", { host: "dbhost", port: 5432, database: "mydb" }, "admin", "pw");

    expect(version).toBeUndefined();
  });
});
