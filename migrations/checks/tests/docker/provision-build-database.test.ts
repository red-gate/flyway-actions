const info = vi.fn();
const warning = vi.fn();
const setSecret = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  warning,
  setSecret,
}));

const mockPostgresContainer = {
  getHost: () => "localhost",
  getPort: () => 55432,
  getDatabase: () => "flyway_build",
  getUsername: () => "test",
  getPassword: () => "test",
  stop: vi.fn(),
};

const mockMySqlContainer = {
  getHost: () => "localhost",
  getPort: () => 53306,
  getDatabase: () => "flyway_build",
  getUsername: () => "test",
  getUserPassword: () => "test",
  stop: vi.fn(),
};

const mockSqlServerContainer = {
  getHost: () => "localhost",
  getPort: () => 51433,
  getDatabase: () => "master",
  getUsername: () => "sa",
  getPassword: () => "Flyway_Build_1",
  stop: vi.fn(),
};

const mockGenericContainer = {
  getHost: () => "localhost",
  getMappedPort: () => 51521,
  stop: vi.fn(),
};

vi.doMock("@testcontainers/postgresql", () => ({
  PostgreSqlContainer: class {
    withDatabase() {
      return this;
    }
    withUsername() {
      return this;
    }
    withPassword() {
      return this;
    }
    start() {
      return Promise.resolve(mockPostgresContainer);
    }
  },
}));

vi.doMock("@testcontainers/mssqlserver", () => ({
  MSSQLServerContainer: class {
    acceptLicense() {
      return this;
    }
    start() {
      return Promise.resolve(mockSqlServerContainer);
    }
  },
}));

vi.doMock("@testcontainers/mysql", () => ({
  MySqlContainer: class {
    withDatabase() {
      return this;
    }
    withUsername() {
      return this;
    }
    withUserPassword() {
      return this;
    }
    start() {
      return Promise.resolve(mockMySqlContainer);
    }
  },
}));

vi.doMock("testcontainers", () => ({
  GenericContainer: class {
    withExposedPorts() {
      return this;
    }
    withEnvironment() {
      return this;
    }
    withWaitStrategy() {
      return this;
    }
    start() {
      return Promise.resolve(mockGenericContainer);
    }
  },
  Wait: { forHealthCheck: () => ({}) },
}));

const { provisionBuildDatabase } = await import("../../src/docker/provision-build-database.js");

describe("provisionBuildDatabase", () => {
  beforeEach(() => {
    mockPostgresContainer.stop.mockResolvedValue(undefined);
    mockMySqlContainer.stop.mockResolvedValue(undefined);
    mockSqlServerContainer.stop.mockResolvedValue(undefined);
    mockGenericContainer.stop.mockResolvedValue(undefined);
  });

  it("should return undefined for unknown JDBC URL", async () => {
    const result = await provisionBuildDatabase("jdbc:unknown://localhost/db");

    expect(result).toBeUndefined();
  });

  it("should provision postgresql container and return connection details", async () => {
    const result = await provisionBuildDatabase("jdbc:postgresql://localhost:5432/mydb");

    expect(result).toBeDefined();
    expect(result!.jdbcUrl).toBe("jdbc:postgresql://localhost:55432/flyway_build");
    expect(result!.user).toBe("test");
    expect(result!.password).toBe("test");
  });

  it("should provision sqlserver container and return connection details", async () => {
    const result = await provisionBuildDatabase("jdbc:sqlserver://localhost:1433;databaseName=mydb");

    expect(result).toBeDefined();
    expect(result!.jdbcUrl).toBe("jdbc:sqlserver://localhost:51433;encrypt=false;trustServerCertificate=true");
    expect(result!.user).toBe("sa");
    expect(result!.password).toBe("Flyway_Build_1");
  });

  it("should provision mysql container and return connection details", async () => {
    const result = await provisionBuildDatabase("jdbc:mysql://localhost:3306/mydb");

    expect(result).toBeDefined();
    expect(result!.jdbcUrl).toBe("jdbc:mysql://localhost:53306/flyway_build");
    expect(result!.user).toBe("test");
    expect(result!.password).toBe("test");
  });

  it("should provision oracle container and return connection details", async () => {
    const result = await provisionBuildDatabase("jdbc:oracle:thin:@localhost:1521/xepdb1");

    expect(result).toBeDefined();
    expect(result!.jdbcUrl).toBe("jdbc:oracle:thin:@localhost:51521/xepdb1");
    expect(result!.user).toBe("system");
    expect(result!.password).toBe("test");
  });

  it("should mask password via core.setSecret", async () => {
    await provisionBuildDatabase("jdbc:postgresql://localhost:5432/mydb");

    expect(setSecret).toHaveBeenCalledWith("test");
  });

  it("should provide cleanup function that stops the container", async () => {
    const result = await provisionBuildDatabase("jdbc:postgresql://localhost:5432/mydb");
    await result!.cleanup();

    expect(mockPostgresContainer.stop).toHaveBeenCalled();
  });

  it("should warn but not throw when cleanup fails", async () => {
    mockPostgresContainer.stop.mockRejectedValueOnce(new Error("stop failed"));

    const result = await provisionBuildDatabase("jdbc:postgresql://localhost:5432/mydb");
    await result!.cleanup();

    expect(warning).toHaveBeenCalledWith(expect.stringContaining("stop failed"));
  });

  it("should provision sqlite with a temp file JDBC URL", async () => {
    const result = await provisionBuildDatabase("jdbc:sqlite:mydb.db");

    expect(result).toBeDefined();
    expect(result!.jdbcUrl).toMatch(/^jdbc:sqlite:.*flyway_build.*\.db$/);
    expect(result!.user).toBe("");
    expect(result!.password).toBe("");
  });

  it("should remove sqlite temp file on cleanup", async () => {
    const result = await provisionBuildDatabase("jdbc:sqlite:mydb.db");
    const dbFile = result!.jdbcUrl.replace("jdbc:sqlite:", "");

    await result!.cleanup();

    expect(info).toHaveBeenCalledWith("SQLite build database removed");

    const { existsSync } = await import("node:fs");

    expect(existsSync(dbFile)).toBe(false);
  });
});
