import type { FlywayMigrationsUndoInputs } from "../../src/types.js";
import { mockExec } from "@flyway-actions/shared/test-utils";

const setOutput = vi.fn();
const info = vi.fn();
const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  error: vi.fn(),
  startGroup: vi.fn(),
  endGroup: vi.fn(),
  setOutput,
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { getUndoArgs, undo, parseFlywayOutput } = await import("../../src/flyway/undo.js");

describe("undo", () => {
  it("should set all outputs on success", async () => {
    exec.mockImplementation(mockExec({ stdout: { migrationsUndone: 3, targetSchemaVersion: "2.0" } }));

    const result = await undo({ targetUrl: "jdbc:sqlite:test.db" });

    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
    expect(setOutput).toHaveBeenCalledWith("migrations-undone", "3");
    expect(setOutput).toHaveBeenCalledWith("schema-version", "2.0");
    expect(result).toEqual({ migrationsUndone: 3, schemaVersion: "2.0" });
  });

  it("should log and not error when database has no licensed comparison capability", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          error: {
            errorCode: "COMPARISON_DATABASE_NOT_SUPPORTED",
            message: "No licensed comparison capability found for database type",
          },
        },
        exitCode: 1,
      }),
    );

    const result = await undo({ targetUrl: "jdbc:h2:mem:test" });

    expect(info).toHaveBeenCalledWith(
      "No snapshot was generated or stored in the target database as snapshots are not supported for this database type.",
    );
    expect(result).toEqual({ migrationsUndone: 0, schemaVersion: "unknown" });
  });

  it("should throw when undo fails with an unrecognised error", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          error: {
            errorCode: "FAULT",
            message: "Something went wrong",
          },
        },
        exitCode: 1,
      }),
    );

    await expect(undo({ targetUrl: "jdbc:h2:mem:test" })).rejects.toThrow("Flyway undo failed with exit code 1");
  });
});

describe("parseFlywayOutput", () => {
  it("should parse migrationsUndone and targetSchemaVersion from JSON", () => {
    const stdout = JSON.stringify({ database: "testdb", migrationsUndone: 5, targetSchemaVersion: "3.0" });

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsUndone).toBe(5);
    expect(result.schemaVersion).toBe("3.0");
  });

  it("should handle zero migrations", () => {
    const stdout = JSON.stringify({ migrationsUndone: 0, targetSchemaVersion: "2.0" });

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsUndone).toBe(0);
    expect(result.schemaVersion).toBe("2.0");
  });

  it("should return defaults for empty string", () => {
    const result = parseFlywayOutput("");

    expect(result.migrationsUndone).toBe(0);
    expect(result.schemaVersion).toBe("unknown");
  });

  it("should return defaults for invalid JSON", () => {
    const result = parseFlywayOutput("not valid json");

    expect(result.migrationsUndone).toBe(0);
    expect(result.schemaVersion).toBe("unknown");
  });

  it("should handle null targetSchemaVersion", () => {
    const stdout = JSON.stringify({ migrationsUndone: 1, targetSchemaVersion: null });

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsUndone).toBe(1);
    expect(result.schemaVersion).toBe("unknown");
  });

  it("should default migrationsUndone to zero when missing", () => {
    const stdout = JSON.stringify({ targetSchemaVersion: "4.0" });

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsUndone).toBe(0);
    expect(result.schemaVersion).toBe("4.0");
  });
});

describe("getUndoArgs", () => {
  it("should build args with defaults only", () => {
    const inputs: FlywayMigrationsUndoInputs = {};

    const args = getUndoArgs(inputs);

    expect(args).toContain("undo");
    expect(args.some((a) => a.includes("saveSnapshot"))).toBe(false);
  });

  describe("target params", () => {
    it("should use flat params with no environment", () => {
      const inputs: FlywayMigrationsUndoInputs = {
        targetUrl: "jdbc:postgresql://localhost/db",
        targetUser: "admin",
        targetPassword: "secret",
        targetSchemas: "public,audit",
      };

      const args = getUndoArgs(inputs);

      expect(args).toContain("-url=jdbc:postgresql://localhost/db");
      expect(args).toContain("-user=admin");
      expect(args).toContain("-password=secret");
      expect(args).toContain("-schemas=public,audit");
    });

    it("should use flat params with default environment", () => {
      const inputs: FlywayMigrationsUndoInputs = {
        targetEnvironment: "default",
        targetUrl: "jdbc:postgresql://localhost/db",
        targetUser: "admin",
        targetPassword: "secret",
        targetSchemas: "public,audit",
      };

      const args = getUndoArgs(inputs);

      expect(args).toContain("-environment=default");
      expect(args).toContain("-url=jdbc:postgresql://localhost/db");
      expect(args).toContain("-user=admin");
      expect(args).toContain("-password=secret");
      expect(args).toContain("-schemas=public,audit");
    });

    it("should scope params to named environment", () => {
      const inputs: FlywayMigrationsUndoInputs = {
        targetEnvironment: "production",
        targetUrl: "jdbc:postgresql://localhost/db",
        targetUser: "admin",
        targetPassword: "secret",
        targetSchemas: "public,audit",
      };

      const args = getUndoArgs(inputs);

      expect(args).toContain("-environment=production");
      expect(args).toContain("-environments.production.url=jdbc:postgresql://localhost/db");
      expect(args).toContain("-environments.production.user=admin");
      expect(args).toContain("-environments.production.password=secret");
      expect(args).toContain("-environments.production.schemas=public,audit");
    });
  });

  it("should build args with target-migration-version", () => {
    const inputs: FlywayMigrationsUndoInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      targetMigrationVersion: "5.0",
    };

    const args = getUndoArgs(inputs);

    expect(args).toContain("-target=5.0");
  });

  it("should build args with cherry-pick", () => {
    const inputs: FlywayMigrationsUndoInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      cherryPick: "2.0,2.1",
    };

    const args = getUndoArgs(inputs);

    expect(args).toContain("-cherryPick=2.0,2.1");
  });

  it("should include -undo.saveSnapshot=true when saveSnapshot is true", () => {
    const inputs: FlywayMigrationsUndoInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      saveSnapshot: true,
    };

    const args = getUndoArgs(inputs);

    expect(args).toContain("-undo.saveSnapshot=true");
  });

  it("should omit -saveSnapshot when saveSnapshot is not set", () => {
    const inputs: FlywayMigrationsUndoInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
    };

    const args = getUndoArgs(inputs);

    expect(args.some((a) => a.includes("saveSnapshot"))).toBe(false);
  });

  it("should include working directory", () => {
    const inputs: FlywayMigrationsUndoInputs = {
      workingDirectory: "/app/db",
    };

    const args = getUndoArgs(inputs);

    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should include extra args", () => {
    const inputs: FlywayMigrationsUndoInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      extraArgs: "-X -custom=value",
    };

    const args = getUndoArgs(inputs);

    expect(args).toContain("-X");
    expect(args).toContain("-custom=value");
  });

  it("should not include undefined optional values", () => {
    const inputs: FlywayMigrationsUndoInputs = {};

    const args = getUndoArgs(inputs);

    expect(args.filter((a) => a.includes("url")).length).toBe(0);
    expect(args.filter((a) => a.includes("user")).length).toBe(0);
    expect(args.filter((a) => a.includes("password")).length).toBe(0);
    expect(args.filter((a) => a.includes("environment")).length).toBe(0);
    expect(args.filter((a) => a.includes("target")).length).toBe(0);
    expect(args.filter((a) => a.includes("cherryPick")).length).toBe(0);
  });
});
