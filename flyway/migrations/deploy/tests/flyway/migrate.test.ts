import type { ExecOptions } from "@actions/exec";
import type { FlywayMigrationsDeploymentInputs } from "../../src/types.js";

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

const { buildFlywayMigrateArgs, migrate, parseFlywayOutput } = await import("../../src/flyway/migrate.js");

describe("migrate", () => {
  it("should set all outputs on success", async () => {
    exec.mockImplementation(async (_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(
        Buffer.from('Successfully applied 3 migrations to schema "main", now at version v2.0'),
      );
      return 0;
    });

    await migrate({ url: "jdbc:sqlite:test.db" });

    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
    expect(setOutput).toHaveBeenCalledWith("migrations-applied", "3");
    expect(setOutput).toHaveBeenCalledWith("schema-version", "2.0");
  });
});

describe("parseFlywayOutput", () => {
  it("should parse migration count from success message", () => {
    const stdout = `
      Flyway Community Edition 10.0.0 by Redgate
      Database: jdbc:postgresql://localhost/test
      Successfully applied 3 migrations to schema "public" (execution time 00:00.150s)
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(3);
  });

  it("should parse schema version", () => {
    const stdout = `
      Flyway Community Edition 10.0.0 by Redgate
      Database: jdbc:postgresql://localhost/test
      Schema version: 2.0.1
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.schemaVersion).toBe("2.0.1");
  });

  it("should parse current version of schema format", () => {
    const stdout = `
      Current version of schema "public": 1.5
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.schemaVersion).toBe("1.5");
  });

  it("should return defaults when no patterns match", () => {
    const stdout = "Some unrelated output";

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(0);
    expect(result.schemaVersion).toBe("unknown");
  });

  it("should parse JSON output if present", () => {
    const stdout = `
      {"schemaVersion": "3.0", "migrationsExecuted": 5}
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(5);
    expect(result.schemaVersion).toBe("3.0");
  });

  it("should not count validated migrations as applied", () => {
    const stdout = `
      Successfully validated 10 migrations
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(0);
  });

  it("should handle zero migrations", () => {
    const stdout = `
      Schema "public" is up to date. No migration necessary.
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(0);
  });

  it("should handle empty string", () => {
    const result = parseFlywayOutput("");
    expect(result.migrationsApplied).toBe(0);
    expect(result.schemaVersion).toBe("unknown");
  });

  it("should fall back to regex when JSON is malformed", () => {
    const stdout = `
      Successfully applied 2 migrations
      Schema version: 4.0
      {"schemaVersion": broken json}
    `;

    const result = parseFlywayOutput(stdout);

    expect(result.migrationsApplied).toBe(2);
    expect(result.schemaVersion).toBe("4.0");
  });
});

describe("buildFlywayMigrateArgs", () => {
  it("should build args with defaults only", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {};

    const args = buildFlywayMigrateArgs(inputs);

    expect(args).toContain("migrate");
    expect(args.some((a) => a.includes("saveSnapshot"))).toBe(false);
  });

  it("should build args with url connection", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      url: "jdbc:postgresql://localhost/db",
      user: "admin",
      password: "secret",
    };

    const args = buildFlywayMigrateArgs(inputs);

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
    expect(args).toContain("-user=admin");
    expect(args).toContain("-password=secret");
  });

  it("should build args with environment", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      environment: "production",
    };

    const args = buildFlywayMigrateArgs(inputs);

    expect(args).toContain("-environment=production");
  });

  it("should build args with target", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      url: "jdbc:postgresql://localhost/db",
      target: "5.0",
    };

    const args = buildFlywayMigrateArgs(inputs);

    expect(args).toContain("-target=5.0");
  });

  it("should build args with cherry-pick", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      url: "jdbc:postgresql://localhost/db",
      cherryPick: "2.0,2.1",
    };

    const args = buildFlywayMigrateArgs(inputs);

    expect(args).toContain("-cherryPick=2.0,2.1");
  });

  it("should include -saveSnapshot=true when saveSnapshot is true", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      url: "jdbc:postgresql://localhost/db",
      saveSnapshot: true,
    };

    const args = buildFlywayMigrateArgs(inputs);

    expect(args).toContain("-saveSnapshot=true");
  });

  it("should omit -saveSnapshot when saveSnapshot is not set", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      url: "jdbc:postgresql://localhost/db",
    };

    const args = buildFlywayMigrateArgs(inputs);

    expect(args.some((a) => a.includes("saveSnapshot"))).toBe(false);
  });

  it("should include working directory", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      workingDirectory: "/app/db",
    };

    const args = buildFlywayMigrateArgs(inputs);

    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should include extra args", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      url: "jdbc:postgresql://localhost/db",
      extraArgs: "-X -custom=value",
    };

    const args = buildFlywayMigrateArgs(inputs);

    expect(args).toContain("-X");
    expect(args).toContain("-custom=value");
  });

  it("should not include undefined optional values", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {};

    const args = buildFlywayMigrateArgs(inputs);

    expect(args.filter((a) => a.includes("url")).length).toBe(0);
    expect(args.filter((a) => a.includes("user")).length).toBe(0);
    expect(args.filter((a) => a.includes("password")).length).toBe(0);
    expect(args.filter((a) => a.includes("environment")).length).toBe(0);
    expect(args.filter((a) => a.includes("target")).length).toBe(0);
    expect(args.filter((a) => a.includes("cherryPick")).length).toBe(0);
  });
});
