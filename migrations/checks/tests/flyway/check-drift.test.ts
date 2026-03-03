import type { FlywayMigrationsChecksInputs } from "../../src/types.js";
import * as path from "node:path";
import { mockExec } from "@flyway-actions/shared/test-utils";

const info = vi.fn();
const setOutput = vi.fn();
const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  error: vi.fn(),
  setOutput,
  startGroup: vi.fn(),
  endGroup: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { getDriftArgs, runCheckDrift } = await import("../../src/flyway/check-drift.js");

const baseInputs: FlywayMigrationsChecksInputs = {};

describe("getDriftArgs", () => {
  it("should return args with -drift for enterprise edition", () => {
    const args = getDriftArgs(baseInputs, "enterprise");

    expect(args).toBeDefined();
    expect(args![0]).toBe("check");
    expect(args).toContain("-drift");
  });

  it("should include -check.failOnDrift=true when failOnDrift is true", () => {
    const args = getDriftArgs({ failOnDrift: true }, "enterprise");

    expect(args).toContain("-check.failOnDrift=true");
  });

  it("should not include -check.failOnDrift=true when failOnDrift is false", () => {
    const args = getDriftArgs({ failOnDrift: false }, "enterprise");

    expect(args).not.toContain("-check.failOnDrift=true");
  });

  it("should include target args but not target migration version or cherry pick", () => {
    const args = getDriftArgs(
      { targetUrl: "jdbc:postgresql://localhost/db", targetMigrationVersion: "5.0", cherryPick: "3.0" },
      "enterprise",
    );

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
    expect(args).not.toContain("-target=5.0");
    expect(args).not.toContain("-cherryPick=3.0");
  });

  it("should not include build environment args", () => {
    const args = getDriftArgs({ buildUrl: "jdbc:sqlite:build.db" }, "enterprise");

    expect(args).not.toContain(expect.stringContaining("default_build"));
  });

  it("should return undefined for community edition", () => {
    expect(getDriftArgs(baseInputs, "community")).toBeUndefined();
    expect(info).toHaveBeenCalledWith("Skipping drift check: not available in Community edition");
  });

  it("should return undefined for teams edition", () => {
    expect(getDriftArgs(baseInputs, "teams")).toBeUndefined();
    expect(info).toHaveBeenCalledWith("Skipping drift check: not available in Teams edition");
  });

  it("should return undefined when skipDriftCheck is true", () => {
    expect(getDriftArgs({ skipDriftCheck: true }, "enterprise")).toBeUndefined();
    expect(info).toHaveBeenCalledWith(expect.stringContaining("Skipping drift check"));
  });

  it("should return undefined when skipDriftCheck is true even if failOnDrift is true", () => {
    expect(getDriftArgs({ skipDriftCheck: true, failOnDrift: true }, "enterprise")).toBeUndefined();
  });
});

describe("runDriftCheck", () => {
  it("should return undefined when edition is not enterprise", async () => {
    const result = await runCheckDrift(baseInputs, "community");

    expect(result).toBeUndefined();
  });

  it("should set drift-detected to false when exit code is 0 and no drift in output", async () => {
    exec.mockImplementation(mockExec({ stdout: { individualResults: [{ operation: "drift" }] } }));

    await runCheckDrift(baseInputs, "enterprise");

    expect(setOutput).toHaveBeenCalledWith("drift-detected", "false");
  });

  it("should set drift-detected to true when exit code is 0 and drift detected in output", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          individualResults: [{ operation: "drift", differences: [{ name: "Table_1" }] }],
        },
      }),
    );

    await runCheckDrift(baseInputs, "enterprise");

    expect(setOutput).toHaveBeenCalledWith("drift-detected", "true");
  });

  it("should set drift-detected and drift-resolution-folder when exit code is non-zero and error code is CHECK_DRIFT_DETECTED", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          error: {
            errorCode: "CHECK_DRIFT_DETECTED",
            message: "Drift detected",
            driftResolutionFolderPath: "drift-scripts",
          },
        },
        exitCode: 1,
      }),
    );

    await runCheckDrift(baseInputs, "enterprise");

    expect(setOutput).toHaveBeenCalledWith("drift-detected", "true");
    expect(setOutput).toHaveBeenCalledWith("drift-resolution-folder", "drift-scripts");
  });

  it("should return exit code 0 when database does not support comparison", async () => {
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

    const result = await runCheckDrift(baseInputs, "enterprise");

    expect(result?.exitCode).toBe(0);
    expect(setOutput).not.toHaveBeenCalled();
    expect(info).toHaveBeenCalledWith(
      "Drift check could not be run because advanced comparison features are not supported for this database type.",
    );
  });

  it("should not set drift-detected when exit code is non-zero and error code is not CHECK_DRIFT_DETECTED", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: { error: { errorCode: "FAULT", message: "Something else failed" } },
        exitCode: 1,
      }),
    );

    await runCheckDrift(baseInputs, "enterprise");

    expect(setOutput).not.toHaveBeenCalled();
  });

  it("should return reportPath from parsed output", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          htmlReport: "custom-report.html",
          individualResults: [{ operation: "drift" }],
        },
      }),
    );

    const result = await runCheckDrift(baseInputs, "enterprise");

    expect(result?.reportPath).toBe("custom-report.html");
  });

  it("should return undefined reportPath when output has no htmlReport", async () => {
    exec.mockImplementation(mockExec({ stdout: { individualResults: [{ operation: "drift" }] } }));

    const result = await runCheckDrift(baseInputs, "enterprise");

    expect(result?.reportPath).toBeUndefined();
  });

  it("should set drift-resolution-folder output when present in drift result", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          individualResults: [{ operation: "drift", driftResolutionFolder: "drift-scripts" }],
        },
      }),
    );

    await runCheckDrift(baseInputs, "enterprise");

    expect(setOutput).toHaveBeenCalledWith("drift-resolution-folder", "drift-scripts");
  });

  it("should not set drift-resolution-folder output when not present", async () => {
    exec.mockImplementation(mockExec({ stdout: { individualResults: [{ operation: "drift" }] } }));

    await runCheckDrift(baseInputs, "enterprise");

    expect(setOutput).not.toHaveBeenCalledWith("drift-resolution-folder", expect.anything());
  });

  it("should prepend working directory to drift-resolution-folder", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          individualResults: [{ operation: "drift", driftResolutionFolder: "drift-scripts" }],
        },
      }),
    );

    await runCheckDrift({ workingDirectory: "my-project" }, "enterprise");

    expect(setOutput).toHaveBeenCalledWith("drift-resolution-folder", path.join("my-project", "drift-scripts"));
  });

  it("should not prepend working directory when drift-resolution-folder is absolute", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: {
          individualResults: [{ operation: "drift", driftResolutionFolder: "/tmp/drift-scripts" }],
        },
      }),
    );

    await runCheckDrift({ workingDirectory: "my-project" }, "enterprise");

    expect(setOutput).toHaveBeenCalledWith("drift-resolution-folder", "/tmp/drift-scripts");
  });
});
