import type { CheckFlags } from "../../src/flyway/run-checks.js";
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

const baseInputs: FlywayMigrationsChecksInputs = {
  generateReport: true,
  failOnDrift: true,
  failOnCodeReview: true,
};

const allFlags: CheckFlags = {
  code: true,
  drift: true,
  changes: true,
  dryrun: true,
};

describe("buildCheckArgs", () => {
  it("should include all check flags when all enabled", () => {
    const args = buildCheckArgs(baseInputs, allFlags);

    expect(args[0]).toBe("check");
    expect(args).toContain("-code");
    expect(args).toContain("-drift");
    expect(args).toContain("-changes");
    expect(args).toContain("-dryrun");
  });

  it("should only include enabled check flags", () => {
    const flags: CheckFlags = { code: true, drift: false, changes: false, dryrun: false };
    const args = buildCheckArgs(baseInputs, flags);

    expect(args).toContain("-code");
    expect(args).not.toContain("-drift");
    expect(args).not.toContain("-changes");
    expect(args).not.toContain("-dryrun");
  });

  it("should include target args", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      targetUrl: "jdbc:postgresql://localhost/db",
      targetUser: "admin",
    };

    const args = buildCheckArgs(inputs, allFlags);

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
    expect(args).toContain("-user=admin");
  });

  it("should include build env args only when changes flag is set", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      buildEnvironment: "shadow",
    };

    const withChanges = buildCheckArgs(inputs, allFlags);
    const withoutChanges = buildCheckArgs(inputs, { ...allFlags, changes: false });

    expect(withChanges).toContain("-buildEnvironment=shadow");
    expect(withoutChanges).not.toContain("-buildEnvironment=shadow");
  });

  it("should include base args", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      workingDirectory: "/app/db",
      extraArgs: "-X",
    };

    const args = buildCheckArgs(inputs, allFlags);

    expect(args).toContain("-workingDirectory=/app/db");
    expect(args).toContain("-X");
  });

  it("should include failOnError when failOnCodeReview is true", () => {
    const args = buildCheckArgs(baseInputs, allFlags);

    expect(args).toContain("-failOnError=true");
  });

  it("should not include failOnError when failOnCodeReview is false", () => {
    const inputs: FlywayMigrationsChecksInputs = { ...baseInputs, failOnCodeReview: false };
    const args = buildCheckArgs(inputs, allFlags);

    expect(args).not.toContain("-failOnError=true");
  });

  it("should include failOnDrift when failOnDrift is true", () => {
    const inputs: FlywayMigrationsChecksInputs = { ...baseInputs, failOnDrift: true };
    const args = buildCheckArgs(inputs, allFlags);

    expect(args).toContain("-failOnDrift=true");
  });

  it("should not include failOnDrift when failOnDrift is false", () => {
    const inputs: FlywayMigrationsChecksInputs = { ...baseInputs, failOnDrift: false };
    const args = buildCheckArgs(inputs, allFlags);

    expect(args).not.toContain("-failOnDrift=true");
  });

  it("should include target migration version and cherry pick", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      targetMigrationVersion: "5.0",
      cherryPick: "3.0,4.0",
    };

    const args = buildCheckArgs(inputs, allFlags);

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

    const exitCode = await runChecks(baseInputs, allFlags);

    expect(exitCode).toBe(0);
  });

  it("should return non-zero exit code on failure", async () => {
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stderr?.(Buffer.from("Check failed"));
      return Promise.resolve(1);
    });

    const exitCode = await runChecks(baseInputs, allFlags);

    expect(exitCode).toBe(1);
  });
});
