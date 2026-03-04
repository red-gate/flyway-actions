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

const { getCheckDriftArgs, checkForDrift } = await import("../../src/flyway/check-for-drift.js");

describe("checkForDrift", () => {
  it("should set drift-detected to false and exit-code to 0 when exit code is 0", async () => {
    exec.mockResolvedValue(0);

    const result = await checkForDrift({ targetUrl: "jdbc:sqlite:test.db" });

    expect(result).toEqual({ driftDetected: false, comparisonSupported: true });
    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
    expect(setOutput).toHaveBeenCalledWith("drift-detected", "false");
  });

  it("should set drift-detected output to true when error code is CHECK_DRIFT_DETECTED", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: { error: { errorCode: "CHECK_DRIFT_DETECTED", message: "Drift detected" } },
        exitCode: 1,
      }),
    );

    const result = await checkForDrift({ targetUrl: "jdbc:sqlite:test.db" });

    expect(result).toEqual({ driftDetected: true, comparisonSupported: true });
    expect(setOutput).toHaveBeenCalledWith("exit-code", "1");
    expect(setOutput).toHaveBeenCalledWith("drift-detected", "true");
  });

  it("should set report-path output when drift detected with htmlReport in output", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          error: { errorCode: "CHECK_DRIFT_DETECTED", message: "Drift detected", htmlReport: "drift-report.html" },
        },
        exitCode: 1,
      }),
    );

    await checkForDrift({ targetUrl: "jdbc:sqlite:test.db" });

    expect(setOutput).toHaveBeenCalledWith("report-path", "drift-report.html");
  });

  it("should set drift-resolution-folder output when drift is detected with resolution folder", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          error: {
            errorCode: "CHECK_DRIFT_DETECTED",
            message: "Drift detected",
            driftResolutionFolderPath: "/absolute/path/to/resolution",
          },
        },
        exitCode: 1,
      }),
    );

    await checkForDrift({ targetUrl: "jdbc:sqlite:test.db" });

    expect(setOutput).toHaveBeenCalledWith("drift-resolution-folder", "/absolute/path/to/resolution");
  });

  it("should not set drift-detected when non-drift error occurs", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: { error: { errorCode: "FAULT", message: "Something else failed" } },
        exitCode: 1,
      }),
    );

    await checkForDrift({ targetUrl: "jdbc:sqlite:test.db" });

    expect(setOutput).toHaveBeenCalledWith("exit-code", "1");
    expect(setOutput).not.toHaveBeenCalledWith("drift-detected", expect.anything());
  });

  it("should return no drift and comparison not supported when database does not support comparison", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          error: {
            errorCode: "COMPARISON_DATABASE_NOT_SUPPORTED",
            message: "No comparison capability found that supports both types",
          },
        },
        exitCode: 1,
      }),
    );

    const result = await checkForDrift({ targetUrl: "jdbc:h2:mem:test" });

    expect(result).toEqual({ driftDetected: false, comparisonSupported: false });
    expect(setOutput).not.toHaveBeenCalledWith("drift-detected", expect.anything());
    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
    expect(info).toHaveBeenCalledWith(
      "Drift check could not be run because advanced comparison features are not supported for this database type.",
    );
  });
});

describe("getCheckDriftArgs", () => {
  it("should build args with check and -drift as first elements", () => {
    const inputs: FlywayMigrationsUndoInputs = {};

    const args = getCheckDriftArgs(inputs);

    expect(args[0]).toBe("check");
    expect(args[1]).toBe("-drift");
    expect(args[2]).toBe("-check.failOnDrift=true");
  });

  describe("target params", () => {
    it("should use flat params with no environment", () => {
      const inputs: FlywayMigrationsUndoInputs = {
        targetUrl: "jdbc:postgresql://localhost/db",
        targetUser: "admin",
        targetPassword: "secret",
        targetSchemas: "public,audit",
      };

      const args = getCheckDriftArgs(inputs);

      expect(args).toContain("-url=jdbc:postgresql://localhost/db");
      expect(args).toContain("-user=admin");
      expect(args).toContain("-password=secret");
      expect(args).toContain("-schemas=public,audit");
    });

    it("should use flat params with default environment", () => {
      const inputs: FlywayMigrationsUndoInputs = {
        targetUrl: "jdbc:postgresql://localhost/db",
        targetUser: "admin",
        targetPassword: "secret",
        targetSchemas: "public,audit",
        targetEnvironment: "default",
      };

      const args = getCheckDriftArgs(inputs);

      expect(args).toContain("-environment=default");
      expect(args).toContain("-url=jdbc:postgresql://localhost/db");
      expect(args).toContain("-user=admin");
      expect(args).toContain("-password=secret");
      expect(args).toContain("-schemas=public,audit");
    });

    it("should scope params to named environment", () => {
      const inputs: FlywayMigrationsUndoInputs = {
        targetUrl: "jdbc:postgresql://localhost/db",
        targetUser: "admin",
        targetPassword: "secret",
        targetEnvironment: "production",
        targetSchemas: "public,audit",
      };

      const args = getCheckDriftArgs(inputs);

      expect(args).toContain("-environment=production");
      expect(args).toContain("-environments.production.url=jdbc:postgresql://localhost/db");
      expect(args).toContain("-environments.production.user=admin");
      expect(args).toContain("-environments.production.password=secret");
      expect(args).toContain("-environments.production.schemas=public,audit");
    });
  });

  it("should include workingDirectory and extraArgs", () => {
    const inputs: FlywayMigrationsUndoInputs = {
      workingDirectory: "/app/db",
      extraArgs: "-X -custom=value",
    };

    const args = getCheckDriftArgs(inputs);

    expect(args).toContain("-workingDirectory=/app/db");
    expect(args).toContain("-X");
    expect(args).toContain("-custom=value");
  });

  it("should not include target, cherryPick, or saveSnapshot", () => {
    const inputs: FlywayMigrationsUndoInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      targetMigrationVersion: "5.0",
      cherryPick: "2.0,2.1",
      saveSnapshot: true,
    };

    const args = getCheckDriftArgs(inputs);

    expect(args.some((a) => a.includes("target"))).toBe(false);
    expect(args.some((a) => a.includes("cherryPick"))).toBe(false);
    expect(args.some((a) => a.includes("saveSnapshot"))).toBe(false);
  });
});
