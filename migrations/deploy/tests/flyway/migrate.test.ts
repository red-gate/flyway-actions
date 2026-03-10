import type { FlywayMigrationsDeploymentInputs } from "../../src/types.js";
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

const { getMigrateArgs, migrate, parseFlywayOutput } = await import("../../src/flyway/migrate.js");

describe("migrate", () => {
  it("should set all outputs on success", async () => {
    exec.mockImplementation(mockExec({ stdout: { migrationsExecuted: 3, targetSchemaVersion: "2.0" } }));

    await migrate({ targetUrl: "jdbc:sqlite:test.db" });

    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
    expect(setOutput).toHaveBeenCalledWith("migrations-applied", "3");
    expect(setOutput).toHaveBeenCalledWith("schema-version", "2.0");
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

    await migrate({ targetUrl: "jdbc:h2:mem:test" });

    expect(info).toHaveBeenCalledWith(
      "No snapshot was generated or stored in the target database as snapshots are not supported for this database type.",
    );
  });

  it("should throw when migrate fails with an unrecognised error", async () => {
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

    await expect(migrate({ targetUrl: "jdbc:h2:mem:test" })).rejects.toThrow("Flyway migrate failed with exit code 1");
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
    expect(args.some((a) => a.includes("saveSnapshot"))).toBe(false);
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

  it("should include -baselineOnMigrate=true when baselineOnMigrate is true", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      baselineOnMigrate: true,
    };

    const args = getMigrateArgs(inputs);

    expect(args).toContain("-baselineOnMigrate=true");
  });

  it("should omit -baselineOnMigrate when baselineOnMigrate is not set", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
    };

    const args = getMigrateArgs(inputs);

    expect(args.some((a) => a.includes("baselineOnMigrate"))).toBe(false);
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
});
