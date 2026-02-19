import type { FlywayMigrationsChecksInputs } from "../../src/types.js";
import type { ExecOptions } from "@actions/exec";

const info = vi.fn();
const error = vi.fn();
const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  error,
  startGroup: vi.fn(),
  endGroup: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { getCheckArgs, runChecks } = await import("../../src/flyway/run-checks.js");

const baseInputs: FlywayMigrationsChecksInputs = {};

describe("getCheckArgs", () => {
  it("should include check -dryrun -code -drift by default", () => {
    const args = getCheckArgs(baseInputs, "enterprise");

    expect(args[0]).toBe("check");
    expect(args).toContain("-dryrun");
    expect(args).toContain("-code");
    expect(args).toContain("-drift");
  });

  it("should include -check.failOnError when failOnCodeReview is true", () => {
    const args = getCheckArgs({ ...baseInputs, failOnCodeReview: true }, "enterprise");

    expect(args).toContain("-check.failOnError=true");
  });

  it("should include -check.failOnDrift when failOnDrift is true", () => {
    const args = getCheckArgs({ ...baseInputs, failOnDrift: true }, "enterprise");

    expect(args).toContain("-check.failOnDrift=true");
  });

  it("should not include -check.failOnDrift when failOnDrift is false", () => {
    const args = getCheckArgs({ ...baseInputs, failOnDrift: false }, "enterprise");

    expect(args).not.toContain("-check.failOnDrift=true");
  });

  it("should include both -failOnError and -failOnDrift flags independently", () => {
    const args = getCheckArgs({ ...baseInputs, failOnCodeReview: true, failOnDrift: true }, "enterprise");

    expect(args).toContain("-check.failOnError=true");
    expect(args).toContain("-check.failOnDrift=true");
  });

  it("should include target args", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      targetUrl: "jdbc:postgresql://localhost/db",
      targetUser: "admin",
    };

    const args = getCheckArgs(inputs, "enterprise");

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
    expect(args).toContain("-user=admin");
  });

  it("should include base args", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      workingDirectory: "/app/db",
      extraArgs: "-X",
    };

    const args = getCheckArgs(inputs, "enterprise");

    expect(args).toContain("-workingDirectory=/app/db");
    expect(args).toContain("-X");
  });

  it("should include -changes when build url is provided", () => {
    const args = getCheckArgs({ ...baseInputs, buildUrl: "jdbc:sqlite:build.db" }, "enterprise");

    expect(args).toContain("-changes");
  });

  it("should include -changes when build environment is provided", () => {
    const args = getCheckArgs({ ...baseInputs, buildEnvironment: "build" }, "enterprise");

    expect(args).toContain("-changes");
  });

  it("should not include -changes when no build inputs provided", () => {
    const args = getCheckArgs(baseInputs, "enterprise");

    expect(args).not.toContain("-changes");
  });

  it("should log info when no build inputs provided", () => {
    getCheckArgs(baseInputs, "enterprise");

    expect(info).toHaveBeenCalledWith(expect.stringContaining("Skipping deployment changes report"));
  });

  it("should include build args", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      buildUrl: "jdbc:postgresql://localhost/build-db",
      buildUser: "deploy",
    };

    const args = getCheckArgs(inputs, "enterprise");

    expect(args).toContain("-environments.default_build.url=jdbc:postgresql://localhost/build-db");
    expect(args).toContain("-environments.default_build.user=deploy");
  });

  it("should include target migration version and cherry pick", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      ...baseInputs,
      targetMigrationVersion: "5.0",
      cherryPick: "3.0,4.0",
    };

    const args = getCheckArgs(inputs, "enterprise");

    expect(args).toContain("-target=5.0");
    expect(args).toContain("-cherryPick=3.0,4.0");
  });

  it("should omit -code when skipCodeReview is true", () => {
    const args = getCheckArgs({ ...baseInputs, skipCodeReview: true }, "enterprise");

    expect(args).not.toContain("-code");
  });

  it("should omit -failOnError when skipCodeReview is true even if failOnCodeReview is true", () => {
    const args = getCheckArgs({ ...baseInputs, skipCodeReview: true, failOnCodeReview: true }, "enterprise");

    expect(args).not.toContain("-check.failOnError=true");
  });

  it("should omit -drift when skipDriftCheck is true", () => {
    const args = getCheckArgs({ ...baseInputs, skipDriftCheck: true }, "enterprise");

    expect(args).not.toContain("-drift");
  });

  it("should omit -failOnDrift when skipDriftCheck is true even if failOnDrift is true", () => {
    const args = getCheckArgs({ ...baseInputs, skipDriftCheck: true, failOnDrift: true }, "enterprise");

    expect(args).not.toContain("-check.failOnDrift=true");
  });

  it("should omit -dryrun when skipDeploymentScriptReview is true", () => {
    const args = getCheckArgs({ ...baseInputs, skipDeploymentScriptReview: true }, "enterprise");

    expect(args).not.toContain("-dryrun");
  });

  it("should omit -changes and build args when skipDeploymentChangesReport is true", () => {
    const args = getCheckArgs(
      {
        ...baseInputs,
        skipDeploymentChangesReport: true,
        buildUrl: "jdbc:sqlite:build.db",
      },
      "enterprise",
    );

    expect(args).not.toContain("-changes");
    expect(args).not.toContain("-buildEnvironment=default_build");
    expect(args).not.toContain("-environments.default_build.url=jdbc:sqlite:build.db");
  });

  it("should log info when skipDeploymentScriptReview is true", () => {
    getCheckArgs({ ...baseInputs, skipDeploymentScriptReview: true, buildUrl: "jdbc:sqlite:build.db" }, "enterprise");

    expect(info).toHaveBeenCalledWith(expect.stringContaining("Skipping deployment script review"));
  });

  it("should log info when skipCodeReview is true and build inputs exist", () => {
    getCheckArgs({ ...baseInputs, skipCodeReview: true, buildUrl: "jdbc:sqlite:build.db" }, "enterprise");

    expect(info).toHaveBeenCalledWith(expect.stringContaining("Skipping code review"));
  });

  it("should log info when skipDriftCheck is true and build inputs exist", () => {
    getCheckArgs({ ...baseInputs, skipDriftCheck: true, buildUrl: "jdbc:sqlite:build.db" }, "enterprise");

    expect(info).toHaveBeenCalledWith(expect.stringContaining("Skipping drift check"));
  });

  it("should log info when skipDeploymentChangesReport is true and build inputs exist", () => {
    getCheckArgs({ ...baseInputs, skipDeploymentChangesReport: true, buildUrl: "jdbc:sqlite:build.db" }, "enterprise");

    expect(info).toHaveBeenCalledWith(expect.stringContaining("Skipping deployment changes report"));
  });

  describe("community edition", () => {
    it("should skip -dryrun, -drift, and -changes but keep -code", () => {
      const args = getCheckArgs({ ...baseInputs, buildUrl: "jdbc:sqlite:build.db" }, "community");

      expect(args).toContain("-code");
      expect(args).not.toContain("-dryrun");
      expect(args).not.toContain("-drift");
      expect(args).not.toContain("-changes");
    });

    it("should log skip messages for unavailable checks", () => {
      getCheckArgs(baseInputs, "community");

      expect(info).toHaveBeenCalledWith("Skipping deployment script review: not available in Community edition");
      expect(info).toHaveBeenCalledWith("Skipping drift check: not available in Community edition");
      expect(info).toHaveBeenCalledWith("Skipping deployment changes report: not available in Community edition");
    });
  });

  describe("teams edition", () => {
    it("should include -dryrun and -code but skip -drift and -changes", () => {
      const args = getCheckArgs({ ...baseInputs, buildUrl: "jdbc:sqlite:build.db" }, "teams");

      expect(args).toContain("-dryrun");
      expect(args).toContain("-code");
      expect(args).not.toContain("-drift");
      expect(args).not.toContain("-changes");
    });

    it("should log skip messages for enterprise-only checks", () => {
      getCheckArgs(baseInputs, "teams");

      expect(info).toHaveBeenCalledWith("Skipping drift check: not available in Teams edition");
      expect(info).toHaveBeenCalledWith("Skipping deployment changes report: not available in Teams edition");
    });
  });
});

describe("runChecks", () => {
  it("should return exit code 0 on success", async () => {
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stdout?.(Buffer.from("All checks passed"));
      return Promise.resolve(0);
    });

    const exitCode = await runChecks(baseInputs, "enterprise");

    expect(exitCode).toBe(0);
  });

  it("should return non-zero exit code on failure", async () => {
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stderr?.(Buffer.from("Check failed"));
      return Promise.resolve(1);
    });

    const exitCode = await runChecks(baseInputs, "enterprise");

    expect(exitCode).toBe(1);
  });

  it("should log friendly message when provisioner error and build-ok-to-erase is not set", async () => {
    coreError.mockClear();
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stderr?.(Buffer.from("ERROR: You need to configure a provisioner for the build environment"));
      return Promise.resolve(1);
    });

    await runChecks(baseInputs, "enterprise");

    expect(coreError).toHaveBeenCalledWith(expect.stringContaining("build-ok-to-erase"));
  });

  it("should not log friendly message when provisioner error and build-ok-to-erase is true", async () => {
    coreError.mockClear();
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      options?.listeners?.stderr?.(Buffer.from("ERROR: You need to configure a provisioner for the build environment"));
      return Promise.resolve(1);
    });

    await runChecks({ ...baseInputs, buildOkToErase: true }, "enterprise");

    expect(coreError).not.toHaveBeenCalledWith(expect.stringContaining("build-ok-to-erase"));
  });
});
