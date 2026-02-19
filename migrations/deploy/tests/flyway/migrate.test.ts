import type { FlywayMigrationsDeploymentInputs } from "../../src/types.js";
import type { ExecOptions } from "@actions/exec";

const setOutput = vi.fn();
const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info: vi.fn(),
  error: vi.fn(),
  startGroup: vi.fn(),
  endGroup: vi.fn(),
  setOutput,
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { getMigrateArgs, migrate, parseFlywayOutput } = await import("../../src/flyway/migrate.js");

describe("migrate", () => {
  it("should set all outputs on success", async () => {
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(Buffer.from(JSON.stringify({ migrationsExecuted: 3, targetSchemaVersion: "2.0" })));
      return Promise.resolve(0);
    });

    await migrate({ targetUrl: "jdbc:sqlite:test.db" });

    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
    expect(setOutput).toHaveBeenCalledWith("migrations-applied", "3");
    expect(setOutput).toHaveBeenCalledWith("schema-version", "2.0");
  });
});

describe("parseFlywayOutput", () => {
  it("should parse migrationsExecuted and targetSchemaVersion from JSON", () => {
    const stdout = JSON.stringify({ database: "testdb", migrationsExecuted: 5, targetSchemaVersion: "3.0" });

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(5);
    expect(result.schemaVersion).toBe("3.0");
  });

  it("should handle zero migrations", () => {
    const stdout = JSON.stringify({ migrationsExecuted: 0, targetSchemaVersion: "2.0" });

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(0);
    expect(result.schemaVersion).toBe("2.0");
  });

  it("should return defaults for empty string", () => {
    const result = parseFlywayOutput("");

    expect(result.migrationsApplied).toBe(0);
    expect(result.schemaVersion).toBe("unknown");
  });

  it("should return defaults for invalid JSON", () => {
    const result = parseFlywayOutput("not valid json");

    expect(result.migrationsApplied).toBe(0);
    expect(result.schemaVersion).toBe("unknown");
  });

  it("should handle null targetSchemaVersion", () => {
    const stdout = JSON.stringify({ migrationsExecuted: 1, targetSchemaVersion: null });

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(1);
    expect(result.schemaVersion).toBe("unknown");
  });

  it("should default migrationsExecuted to zero when missing", () => {
    const stdout = JSON.stringify({ targetSchemaVersion: "4.0" });

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(0);
    expect(result.schemaVersion).toBe("4.0");
  });
});

describe("getMigrateArgs", () => {
  it("should build args with defaults only", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {};

    const args = getMigrateArgs(inputs);

    expect(args).toContain("migrate");
    expect(args).toContain("-outputType=json");
    expect(args).toContain("-outputLogsInJson=true");
    expect(args.some((a) => a.includes("saveSnapshot"))).toBe(false);
  });

  describe("target params", () => {
    it("should use flat params with no environment", () => {
      const inputs: FlywayMigrationsDeploymentInputs = {
        targetUrl: "jdbc:postgresql://localhost/db",
        targetUser: "admin",
        targetPassword: "secret",
        targetSchemas: "public,audit",
      };

      const args = getMigrateArgs(inputs);

      expect(args).toContain("-url=jdbc:postgresql://localhost/db");
      expect(args).toContain("-user=admin");
      expect(args).toContain("-password=secret");
      expect(args).toContain("-schemas=public,audit");
    });

    it("should use flat params with default environment", () => {
      const inputs: FlywayMigrationsDeploymentInputs = {
        targetEnvironment: "default",
        targetUrl: "jdbc:postgresql://localhost/db",
        targetUser: "admin",
        targetPassword: "secret",
        targetSchemas: "public,audit",
      };

      const args = getMigrateArgs(inputs);

      expect(args).toContain("-environment=default");
      expect(args).toContain("-url=jdbc:postgresql://localhost/db");
      expect(args).toContain("-user=admin");
      expect(args).toContain("-password=secret");
      expect(args).toContain("-schemas=public,audit");
    });

    it("should scope params to named environment", () => {
      const inputs: FlywayMigrationsDeploymentInputs = {
        targetEnvironment: "production",
        targetUrl: "jdbc:postgresql://localhost/db",
        targetUser: "admin",
        targetPassword: "secret",
        targetSchemas: "public,audit",
      };

      const args = getMigrateArgs(inputs);

      expect(args).toContain("-environment=production");
      expect(args).toContain("-environments.production.url=jdbc:postgresql://localhost/db");
      expect(args).toContain("-environments.production.user=admin");
      expect(args).toContain("-environments.production.password=secret");
      expect(args).toContain("-environments.production.schemas=public,audit");
    });
  });

  it("should build args with target-migration-version", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      targetMigrationVersion: "5.0",
    };

    const args = getMigrateArgs(inputs);

    expect(args).toContain("-target=5.0");
  });

  it("should build args with cherry-pick", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      cherryPick: "2.0,2.1",
    };

    const args = getMigrateArgs(inputs);

    expect(args).toContain("-cherryPick=2.0,2.1");
  });

  it("should include -migrate.saveSnapshot=true when saveSnapshot is true", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      saveSnapshot: true,
    };

    const args = getMigrateArgs(inputs);

    expect(args).toContain("-migrate.saveSnapshot=true");
  });

  it("should omit -saveSnapshot when saveSnapshot is not set", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
    };

    const args = getMigrateArgs(inputs);

    expect(args.some((a) => a.includes("saveSnapshot"))).toBe(false);
  });

  it("should include working directory", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      workingDirectory: "/app/db",
    };

    const args = getMigrateArgs(inputs);

    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should include extra args", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      extraArgs: "-X -custom=value",
    };

    const args = getMigrateArgs(inputs);

    expect(args).toContain("-X");
    expect(args).toContain("-custom=value");
  });

  it("should not include undefined optional values", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {};

    const args = getMigrateArgs(inputs);

    expect(args.filter((a) => a.includes("url")).length).toBe(0);
    expect(args.filter((a) => a.includes("user")).length).toBe(0);
    expect(args.filter((a) => a.includes("password")).length).toBe(0);
    expect(args.filter((a) => a.includes("environment")).length).toBe(0);
    expect(args.filter((a) => a.includes("target")).length).toBe(0);
    expect(args.filter((a) => a.includes("cherryPick")).length).toBe(0);
  });
});
