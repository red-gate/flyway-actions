vi.doMock("node:child_process", () => ({
  execSync: vi.fn(),
}));

const { execSync } = await import("node:child_process");
const mockedExecSync = vi.mocked(execSync);

const { provisionBuildDatabase } = await import("../../src/docker/provision-build-database.js");

describe("provisionBuildDatabase", () => {
  it("should return undefined for unknown JDBC URL", () => {
    const result = provisionBuildDatabase("jdbc:unknown://localhost/db");

    expect(result).toBeUndefined();
  });

  describe("createDatabase provisioner", () => {
    it("should return build URL for postgresql with create-database provisioner", () => {
      const result = provisionBuildDatabase("jdbc:postgresql://dbhost:5432/mydb", "admin", "secret");

      expect(result).toBeDefined();
      expect(result!.jdbcUrl).toBe("jdbc:postgresql://dbhost:5432/flyway_build");
      expect(result!.user).toBe("admin");
      expect(result!.password).toBe("secret");
      expect(result!.provisioner).toBe("create-database");
    });

    it("should return build URL for mysql with create-database provisioner", () => {
      const result = provisionBuildDatabase("jdbc:mysql://dbhost:3306/mydb", "admin", "secret");

      expect(result).toBeDefined();
      expect(result!.jdbcUrl).toBe("jdbc:mysql://dbhost:3306/flyway_build");
      expect(result!.user).toBe("admin");
      expect(result!.password).toBe("secret");
      expect(result!.provisioner).toBe("create-database");
    });

    it("should return build URL for sqlserver with create-database provisioner", () => {
      const result = provisionBuildDatabase("jdbc:sqlserver://dbhost:1433;databaseName=mydb", "sa", "secret");

      expect(result).toBeDefined();
      expect(result!.jdbcUrl).toBe("jdbc:sqlserver://dbhost:1433;databaseName=flyway_build");
      expect(result!.user).toBe("sa");
      expect(result!.password).toBe("secret");
      expect(result!.provisioner).toBe("create-database");
    });

    it("should use empty strings when user and password are not provided", () => {
      const result = provisionBuildDatabase("jdbc:postgresql://dbhost:5432/mydb");

      expect(result!.user).toBe("");
      expect(result!.password).toBe("");
    });

    it("should have a no-op cleanup function", async () => {
      const result = provisionBuildDatabase("jdbc:postgresql://dbhost:5432/mydb");

      await expect(result!.cleanup()).resolves.not.toThrow();
    });
  });

  describe("oracle docker provisioner", () => {
    it("should start oracle container and return connection details", () => {
      mockedExecSync
        .mockReturnValueOnce(Buffer.from("container-id"))
        .mockReturnValueOnce("healthy")
        .mockReturnValueOnce("0.0.0.0:51521");

      const result = provisionBuildDatabase("jdbc:oracle:thin:@localhost:1521/xepdb1");

      expect(result).toBeDefined();
      expect(result!.jdbcUrl).toBe("jdbc:oracle:thin:@localhost:51521/xepdb1");
      expect(result!.user).toBe("system");
      expect(result!.password).toBe("test");
      expect(result!.provisioner).toBeUndefined();
    });

    it("should call docker run with correct arguments", () => {
      mockedExecSync
        .mockReturnValueOnce(Buffer.from("container-id"))
        .mockReturnValueOnce("healthy")
        .mockReturnValueOnce("0.0.0.0:51521");

      provisionBuildDatabase("jdbc:oracle:thin:@localhost:1521/xepdb1");

      expect(mockedExecSync).toHaveBeenCalledWith(
        expect.stringContaining("docker run -d --name"),
        expect.objectContaining({ stdio: "pipe" }),
      );
    });

    it("should cleanup by removing the container", async () => {
      mockedExecSync
        .mockReturnValueOnce(Buffer.from("container-id"))
        .mockReturnValueOnce("healthy")
        .mockReturnValueOnce("0.0.0.0:51521");

      const result = provisionBuildDatabase("jdbc:oracle:thin:@localhost:1521/xepdb1");
      await result!.cleanup();

      expect(mockedExecSync).toHaveBeenCalledWith(
        expect.stringContaining("docker rm -f"),
        expect.objectContaining({ stdio: "pipe" }),
      );
    });
  });

  describe("sqlite provisioner", () => {
    it("should provision sqlite with a temp file JDBC URL", () => {
      const result = provisionBuildDatabase("jdbc:sqlite:mydb.db");

      expect(result).toBeDefined();
      expect(result!.jdbcUrl).toMatch(/^jdbc:sqlite:.*flyway_build.*\.db$/);
      expect(result!.user).toBe("");
      expect(result!.password).toBe("");
      expect(result!.provisioner).toBeUndefined();
    });

    it("should remove sqlite temp file on cleanup", async () => {
      const result = provisionBuildDatabase("jdbc:sqlite:mydb.db");
      const dbFile = result!.jdbcUrl.replace("jdbc:sqlite:", "");

      await result!.cleanup();

      const { existsSync } = await import("node:fs");

      expect(existsSync(dbFile)).toBe(false);
    });
  });
});
