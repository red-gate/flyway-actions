vi.doMock("node:child_process", () => ({
  execSync: vi.fn(),
}));

vi.doMock("@actions/core", () => ({
  info: vi.fn(),
}));

const { execSync } = await import("node:child_process");
const mockedExecSync = vi.mocked(execSync);

const { provisionBuildDatabase } = await import("../../src/docker/provision-build-database.js");

describe("provisionBuildDatabase", () => {
  it("should return undefined for unknown JDBC URL", () => {
    const result = provisionBuildDatabase("jdbc:unknown://localhost/db");

    expect(result).toBeUndefined();
  });

  describe("docker container provisioning", () => {
    const setupDockerMocks = (versionOutput: string, portOutput: string) => {
      mockedExecSync
        .mockReturnValueOnce(versionOutput)
        .mockReturnValueOnce(Buffer.from("container-id"))
        .mockReturnValueOnce("healthy")
        .mockReturnValueOnce(portOutput);
    };

    it("should probe version and start versioned postgresql container", () => {
      setupDockerMocks("16.2", "0.0.0.0:55432");

      const result = provisionBuildDatabase("jdbc:postgresql://dbhost:5432/mydb", "admin", "secret");

      expect(result).toBeDefined();
      expect(result!.jdbcUrl).toBe("jdbc:postgresql://localhost:55432/flyway_build");
      expect(result!.user).toBe("flyway_build");
      expect(result!.password).toBe("flyway_build");

      expect(mockedExecSync).toHaveBeenCalledWith(expect.stringContaining("psql"), expect.anything());
      expect(mockedExecSync).toHaveBeenCalledWith(
        expect.stringContaining("postgres:16"),
        expect.objectContaining({ stdio: "pipe" }),
      );
    });

    it("should probe version and start versioned mysql container", () => {
      setupDockerMocks("8.4.3", "0.0.0.0:53306");

      const result = provisionBuildDatabase("jdbc:mysql://dbhost:3306/mydb", "admin", "secret");

      expect(result).toBeDefined();
      expect(result!.jdbcUrl).toBe("jdbc:mysql://localhost:53306/flyway_build");
      expect(result!.user).toBe("flyway_build");
      expect(result!.password).toBe("flyway_build");

      expect(mockedExecSync).toHaveBeenCalledWith(
        expect.stringContaining("mysql:8.4"),
        expect.objectContaining({ stdio: "pipe" }),
      );
    });

    it("should probe version and start versioned sqlserver container", () => {
      setupDockerMocks("16.0.4165.4\n", "0.0.0.0:51433");

      const result = provisionBuildDatabase("jdbc:sqlserver://dbhost:1433;databaseName=mydb", "sa", "secret");

      expect(result).toBeDefined();
      expect(result!.jdbcUrl).toBe("jdbc:sqlserver://localhost:51433;encrypt=false;trustServerCertificate=true");
      expect(result!.user).toBe("sa");
      expect(result!.password).toBe("Flyway_Build_1");

      expect(mockedExecSync).toHaveBeenCalledWith(
        expect.stringContaining("2022-latest"),
        expect.objectContaining({ stdio: "pipe" }),
      );
    });

    it("should start oracle container without version probing", () => {
      mockedExecSync
        .mockReturnValueOnce(Buffer.from("container-id"))
        .mockReturnValueOnce("healthy")
        .mockReturnValueOnce("0.0.0.0:51521");

      const result = provisionBuildDatabase("jdbc:oracle:thin:@dbhost:1521/xepdb1");

      expect(result).toBeDefined();
      expect(result!.jdbcUrl).toBe("jdbc:oracle:thin:@localhost:51521/xepdb1");
      expect(result!.user).toBe("system");
      expect(result!.password).toBe("test");
    });

    it("should use default image when version probe fails", () => {
      mockedExecSync
        .mockImplementationOnce(() => {
          throw new Error("connection refused");
        })
        .mockReturnValueOnce(Buffer.from("container-id"))
        .mockReturnValueOnce("healthy")
        .mockReturnValueOnce("0.0.0.0:55432");

      const result = provisionBuildDatabase("jdbc:postgresql://dbhost:5432/mydb", "admin", "secret");

      expect(result).toBeDefined();
      expect(mockedExecSync).toHaveBeenCalledWith(
        expect.stringContaining("docker run") && expect.not.stringContaining("postgres:"),
        expect.anything(),
      );
    });

    it("should cleanup by removing the container", async () => {
      setupDockerMocks("16.2", "0.0.0.0:55432");

      const result = provisionBuildDatabase("jdbc:postgresql://dbhost:5432/mydb", "admin", "secret");
      await result!.cleanup();

      expect(mockedExecSync).toHaveBeenCalledWith(
        expect.stringContaining("docker rm -f"),
        expect.objectContaining({ stdio: "pipe" }),
      );
    });

    it("should throw when container becomes unhealthy", () => {
      mockedExecSync
        .mockReturnValueOnce("16.2")
        .mockReturnValueOnce(Buffer.from("container-id"))
        .mockReturnValueOnce("unhealthy");

      expect(() => provisionBuildDatabase("jdbc:postgresql://dbhost:5432/mydb", "admin", "secret")).toThrow(
        "Container became unhealthy",
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
