import type { FlywayMigrationsChecksInputs } from "../../src/types.js";
import { mockExec } from "@flyway-actions/shared/test-utils";

const info = vi.fn();
const error = vi.fn();
const setOutput = vi.fn();
const exec = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  error,
  setOutput,
  startGroup: vi.fn(),
  endGroup: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

const { getChangesArgs, runCheckChanges, setChangesOutputs } = await import("../../src/flyway/check-changes.js");

const baseInputs: FlywayMigrationsChecksInputs = {};

describe("getChangesArgs", () => {
  it("should return args with -changes when build url is provided for enterprise", () => {
    const args = getChangesArgs({ buildUrl: "jdbc:sqlite:build.db" }, "enterprise");

    expect(args).toBeDefined();
    expect(args![0]).toBe("check");
    expect(args).toContain("-changes");
  });

  it("should return args with -changes when build environment is provided", () => {
    const args = getChangesArgs({ buildEnvironment: "build" }, "enterprise");

    expect(args).toBeDefined();
    expect(args).toContain("-changes");
  });

  it("should include build environment args", () => {
    const args = getChangesArgs(
      { buildUrl: "jdbc:postgresql://localhost/build-db", buildUser: "deploy" },
      "enterprise",
    );

    expect(args).toContain("-environments.default_build.url=jdbc:postgresql://localhost/build-db");
    expect(args).toContain("-environments.default_build.user=deploy");
  });

  it("should include target and base args", () => {
    const args = getChangesArgs(
      { buildUrl: "jdbc:sqlite:build.db", targetUrl: "jdbc:postgresql://localhost/db", workingDirectory: "/app/db" },
      "enterprise",
    );

    expect(args).toContain("-url=jdbc:postgresql://localhost/db");
    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should include target migration version and cherry pick", () => {
    const args = getChangesArgs(
      { buildUrl: "jdbc:sqlite:build.db", targetMigrationVersion: "5.0", cherryPick: "3.0,4.0" },
      "enterprise",
    );

    expect(args).toContain("-target=5.0");
    expect(args).toContain("-cherryPick=3.0,4.0");
  });

  it("should return undefined when no build inputs provided", () => {
    expect(getChangesArgs(baseInputs, "enterprise")).toBeUndefined();
    expect(info).toHaveBeenCalledWith(expect.stringContaining("Skipping deployment changes report"));
  });

  it("should return undefined for community edition", () => {
    expect(getChangesArgs({ buildUrl: "jdbc:sqlite:build.db" }, "community")).toBeUndefined();
    expect(info).toHaveBeenCalledWith("Skipping deployment changes report: not available in Community edition");
  });

  it("should return undefined for teams edition", () => {
    expect(getChangesArgs({ buildUrl: "jdbc:sqlite:build.db" }, "teams")).toBeUndefined();
    expect(info).toHaveBeenCalledWith("Skipping deployment changes report: not available in Teams edition");
  });

  it("should return undefined when skipDeploymentChangesReport is true", () => {
    expect(
      getChangesArgs({ skipDeploymentChangesReport: true, buildUrl: "jdbc:sqlite:build.db" }, "enterprise"),
    ).toBeUndefined();
    expect(info).toHaveBeenCalledWith(expect.stringContaining("Skipping deployment changes report"));
  });
});

describe("runCheckChanges", () => {
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

    const result = await runCheckChanges({ buildUrl: "jdbc:h2:mem:build" }, "enterprise");

    expect(result?.exitCode).toBe(0);
    expect(info).toHaveBeenCalledWith(
      "Deployment changes report could not be generated because advanced comparison features are not supported for this database type.",
    );
  });
});

describe("setChangesOutputs", () => {
  it("should set changed-object-count from changes result", () => {
    setChangesOutputs({
      individualResults: [
        {
          operation: "changes",
          differences: [{ name: "Table_1" }, { name: "Table_2" }],
          onlyInSource: [{ name: "View_1" }],
        },
      ],
    });

    expect(setOutput).toHaveBeenCalledWith("changed-object-count", "3");
  });

  it("should set changed-object-count to zero when no changes", () => {
    setChangesOutputs({ individualResults: [{ operation: "changes" }] });

    expect(setOutput).toHaveBeenCalledWith("changed-object-count", "0");
  });

  it("should not set changed-object-count when changes result is absent", () => {
    setChangesOutputs({ individualResults: [{ operation: "drift" }] });

    expect(setOutput).not.toHaveBeenCalledWith("changed-object-count", expect.anything());
  });
});
