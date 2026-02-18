import type { FlywayMigrationsChecksInputs } from "../../src/types.js";
import type { ExecOptions } from "@actions/exec";

const exec = vi.fn();
const coreInfo = vi.fn();

vi.doMock("@actions/core", () => ({
  info: coreInfo,
  error: vi.fn(),
  startGroup: vi.fn(),
  endGroup: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { getCheckArgs, runChecks } = await import("../../src/flyway/run-checks.js");

const baseInputs: FlywayMigrationsChecksInputs = {};

describe("getCheckArgs", () => {
  it("should always include check -dryrun -code -drift", () => {
    const args = getCheckArgs(baseInputs);

    expect(args[0]).toBe("check");
    expect(args[1]).toBe("-dryrun");
    expect(args[2]).toBe("-code");
    expect(args[3]).toBe("-drift");
  });

  it("should include -failOnError when failOnCodeReview is true", () => {
    const args = getCheckArgs({ ...baseInputs, failOnCodeReview: true });

    expect(args).toContain("-failOnError=true");
  });

  it("should include -failOnDrift when failOnDrift is true", () => {
    const args = getCheckArgs({ ...baseInputs, failOnDrift: true });

    expect(args).toContain("-failOnDrift=true");
  });

  it("should not include -failOnDrift when failOnDrift is false", () => {
    const args = getCheckArgs({ ...baseInputs, failOnDrift: false });

    expect(args).not.toContain("-failOnDrift=true");
  });

  it("should include both -failOnError and -failOnDrift flags independently", () => {
    const args = getCheckArgs({ ...baseInputs, failOnCodeReview: true, failOnDrift: true });

    expect(args).toContain("-failOnError=true");
    expect(args).toContain("-failOnDrift=true");
  });

  it("should include target args", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      targetUrl: "jdbc:postgresql://localhost/db",
      targetUser: "admin",
    };

    const args = getCheckArgs(inputs);

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
    expect(args).toContain("-user=admin");
  });

  it("should include base args", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      workingDirectory: "/app/db",
      extraArgs: "-X",
    };

    const args = getCheckArgs(inputs);

    expect(args).toContain("-workingDirectory=/app/db");
    expect(args).toContain("-X");
  });

  it("should include -changes when build url is provided", () => {
    const args = getCheckArgs({ ...baseInputs, buildUrl: "jdbc:sqlite:build.db" });

    expect(args).toContain("-changes");
  });

  it("should include -changes when build environment is provided", () => {
    const args = getCheckArgs({ ...baseInputs, buildEnvironment: "build" });

    expect(args).toContain("-changes");
  });

  it("should not include -changes when no build inputs provided", () => {
    const args = getCheckArgs(baseInputs);

    expect(args).not.toContain("-changes");
  });

  it("should log info when no build inputs provided", () => {
    coreInfo.mockClear();
    getCheckArgs(baseInputs);

    expect(coreInfo).toHaveBeenCalledWith(expect.stringContaining("Skipping deployment changes report"));
  });

  it("should include build args", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      buildUrl: "jdbc:postgresql://localhost/build-db",
      buildUser: "deploy",
    };

    const args = getCheckArgs(inputs);

    expect(args).toContain("-environments.default_build.url=jdbc:postgresql://localhost/build-db");
    expect(args).toContain("-environments.default_build.user=deploy");
  });

  it("should include target migration version and cherry pick", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      targetMigrationVersion: "5.0",
      cherryPick: "3.0,4.0",
    };

    const args = getCheckArgs(inputs);

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
