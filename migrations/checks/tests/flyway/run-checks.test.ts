import type { FlywayMigrationsChecksInputs } from "../../src/types.js";
import type { ExecOptions } from "@actions/exec";

const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info: vi.fn(),
  error: vi.fn(),
  startGroup: vi.fn(),
  endGroup: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { buildCheckArgs, runChecks } = await import("../../src/flyway/run-checks.js");

const baseInputs: FlywayMigrationsChecksInputs = {};

describe("buildCheckArgs", () => {
  it("should always include check -dryrun -code", () => {
    const args = buildCheckArgs(baseInputs);

    expect(args[0]).toBe("check");
    expect(args[1]).toBe("-dryrun");
    expect(args[2]).toBe("-code");
  });

  it("should include -failOnError when failOnCodeReview is true", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      failOnCodeReview: true,
    };

    const args = buildCheckArgs(inputs);

    expect(args).toContain("-code");
    expect(args).toContain("-failOnError=true");
  });

  it("should not include -failOnError when failOnCodeReview is false", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      failOnCodeReview: false,
    };

    const args = buildCheckArgs(inputs);

    expect(args).toContain("-code");
    expect(args).not.toContain("-failOnError=true");
  });

  it("should include target args", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      targetUrl: "jdbc:postgresql://localhost/db",
      targetUser: "admin",
    };

    const args = buildCheckArgs(inputs);

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
    expect(args).toContain("-user=admin");
  });

  it("should include base args", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      workingDirectory: "/app/db",
      extraArgs: "-X",
    };

    const args = buildCheckArgs(inputs);

    expect(args).toContain("-workingDirectory=/app/db");
    expect(args).toContain("-X");
  });

  it("should include target migration version and cherry pick", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      targetMigrationVersion: "5.0",
      cherryPick: "3.0,4.0",
    };

    const args = buildCheckArgs(inputs);

    expect(args).toContain("-target=5.0");
    expect(args).toContain("-cherryPick=3.0,4.0");
  });
});

describe("runChecks", () => {
  it("should return exit code 0 on success", async () => {
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(Buffer.from("All checks passed"));
      return Promise.resolve(0);
    });

    const exitCode = await runChecks(baseInputs);

    expect(exitCode).toBe(0);
  });

  it("should return non-zero exit code on failure", async () => {
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stderr?.(Buffer.from("Check failed"));
      return Promise.resolve(1);
    });

    const exitCode = await runChecks(baseInputs);

    expect(exitCode).toBe(1);
  });
});
