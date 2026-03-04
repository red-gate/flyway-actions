import type { FlywayMigrationsChecksInputs } from "../../src/types.js";
import type { ExecOptions } from "@actions/exec";
import * as path from "node:path";
import { mockExec } from "@flyway-actions/shared/test-utils";

const info = vi.fn();
const error = vi.fn();
const warning = vi.fn();
const setOutput = vi.fn();
const setSecret = vi.fn();
const exec = vi.fn();
const provisionBuildDatabase = vi.fn();

vi.doMock("@actions/core", () => ({
  info,
  error,
  warning,
  setOutput,
  setSecret,
  startGroup: vi.fn(),
  endGroup: vi.fn(),
}));

vi.doMock("@actions/exec", () => ({
  exec,
}));

vi.doMock("../../src/docker/provision-build-database.js", () => ({
  provisionBuildDatabase,
}));

const { runChecks } = await import("../../src/flyway/run-checks.js");

const baseInputs: FlywayMigrationsChecksInputs = {};

describe("runChecks", () => {
  it("should not throw on success", async () => {
    exec.mockImplementation(mockExec({ stdout: {} }));

    await expect(runChecks(baseInputs, "enterprise")).resolves.not.toThrow();
  });

  it("should set exit-code to 0 on success", async () => {
    exec.mockImplementation(mockExec({ stdout: {} }));

    await runChecks(baseInputs, "enterprise");

    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
  });

  it("should make separate exec calls for each check type", async () => {
    exec.mockImplementation(mockExec({ stdout: {} }));

    await runChecks(baseInputs, "enterprise");

    const checkCalls = (exec.mock.calls as [string, string[]][]).filter((call) => call[1]?.[0] === "check");

    expect(checkCalls).toHaveLength(3);

    expect(checkCalls[0][1]).toContain("-dryrun");
    expect(checkCalls[0][1]).not.toContain("-code");
    expect(checkCalls[0][1]).not.toContain("-drift");

    expect(checkCalls[1][1]).toContain("-code");
    expect(checkCalls[1][1]).not.toContain("-dryrun");
    expect(checkCalls[1][1]).not.toContain("-drift");

    expect(checkCalls[2][1]).toContain("-drift");
    expect(checkCalls[2][1]).not.toContain("-dryrun");
    expect(checkCalls[2][1]).not.toContain("-code");
  });

  it("should make four exec calls when build url is provided", async () => {
    exec.mockImplementation(mockExec({ stdout: {} }));

    await runChecks({ buildUrl: "jdbc:sqlite:build.db" }, "enterprise");

    const checkCalls = (exec.mock.calls as [string, string[]][]).filter((call) => call[1]?.[0] === "check");

    expect(checkCalls).toHaveLength(4);
    expect(checkCalls[3][1]).toContain("-changes");
  });

  it("should only include build args in the changes invocation", async () => {
    exec.mockImplementation(mockExec({ stdout: {} }));

    await runChecks({ buildUrl: "jdbc:sqlite:build.db" }, "enterprise");

    const checkCalls = (exec.mock.calls as [string, string[]][]).filter((call) => call[1]?.[0] === "check");

    for (let i = 0; i < 3; i++) {
      expect(checkCalls[i][1]).not.toContain(expect.stringContaining("default_build"));
    }

    expect(checkCalls[3][1]).toContain("-environments.default_build.url=jdbc:sqlite:build.db");
  });

  it("should set exit-code from first failed check before throwing", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: { error: { errorCode: "FAULT", message: "Check failed" } },
        exitCode: 1,
      }),
    );

    await expect(runChecks(baseInputs, "enterprise")).rejects.toThrow();
    expect(setOutput).toHaveBeenCalledWith("exit-code", "1");
  });

  it("should throw Flyway checks failed on failure", async () => {
    exec.mockImplementation(
      mockExec({
        stdout: { error: { errorCode: "FAULT", message: "Check failed" } },
        exitCode: 1,
      }),
    );

    await expect(runChecks(baseInputs, "enterprise")).rejects.toThrowError("Flyway checks failed");
  });

  it("should run all checks even if an earlier one fails", async () => {
    let callCount = 0;
    exec.mockImplementation((_cmd: string, _args?: string[], options?: ExecOptions) => {
      callCount++;
      options?.listeners?.stdout?.(Buffer.from("{}"));
      return Promise.resolve(callCount === 1 ? 1 : 0);
    });

    await expect(runChecks(baseInputs, "enterprise")).rejects.toThrow();

    const checkCalls = (exec.mock.calls as [string, string[]][]).filter((call) => call[1]?.[0] === "check");

    expect(checkCalls).toHaveLength(3);
  });

  it("should log friendly message on provisioner error when changes check fails and build-ok-to-erase is not set", async () => {
    exec.mockImplementation((_cmd: string, args?: string[], options?: ExecOptions) => {
      if (args?.includes("-changes")) {
        options?.listeners?.stdout?.(
          Buffer.from(JSON.stringify({ error: { errorCode: "CHECK_BUILD_NO_PROVISIONER" } })),
        );
        return Promise.resolve(1);
      }
      options?.listeners?.stdout?.(Buffer.from("{}"));
      return Promise.resolve(0);
    });

    await expect(runChecks({ buildUrl: "jdbc:sqlite:build.db" }, "enterprise")).rejects.toThrow();
    expect(error).toHaveBeenCalledWith(expect.stringContaining("build-ok-to-erase"));
  });

  it("should not log friendly message on provisioner error when build-ok-to-erase is set", async () => {
    exec.mockImplementation((_cmd: string, args?: string[], options?: ExecOptions) => {
      if (args?.includes("-changes")) {
        options?.listeners?.stdout?.(
          Buffer.from(
            JSON.stringify({
              error: { errorCode: "FAULT", message: "You need to configure a provisioner for the build environment" },
            }),
          ),
        );
        return Promise.resolve(1);
      }
      options?.listeners?.stdout?.(Buffer.from("{}"));
      return Promise.resolve(0);
    });

    await expect(runChecks({ buildUrl: "jdbc:sqlite:build.db", buildOkToErase: true }, "enterprise")).rejects.toThrow();
    expect(error).not.toHaveBeenCalledWith(expect.stringContaining("build-ok-to-erase"));
  });

  it("should set report-path to report.html when no htmlReport in output", async () => {
    exec.mockImplementation(mockExec({ stdout: {} }));

    await runChecks(baseInputs, "enterprise");

    expect(setOutput).toHaveBeenCalledWith("report-path", "report.html");
  });

  it("should set report-path from htmlReport in check output", async () => {
    exec.mockImplementation(mockExec({ stdout: { htmlReport: "custom-report.html" } }));

    await runChecks(baseInputs, "enterprise");

    expect(setOutput).toHaveBeenCalledWith("report-path", "custom-report.html");
  });

  it("should prepend working directory to report-path", async () => {
    exec.mockImplementation(mockExec({ stdout: { htmlReport: "custom-report.html" } }));

    await runChecks({ workingDirectory: "my-project" }, "enterprise");

    expect(setOutput).toHaveBeenCalledWith("report-path", path.join("my-project", "custom-report.html"));
  });

  it("should not prepend working directory when htmlReport is absolute", async () => {
    exec.mockImplementation(mockExec({ stdout: { htmlReport: "/tmp/reports/custom-report.html" } }));

    await runChecks({ workingDirectory: "my-project" }, "enterprise");

    expect(setOutput).toHaveBeenCalledWith("report-path", "/tmp/reports/custom-report.html");
  });
});

describe("auto-provisioning", () => {
  const cleanup = vi.fn().mockResolvedValue(undefined);

  it("should provision build database when conditions are met", async () => {
    provisionBuildDatabase.mockResolvedValue({
      jdbcUrl: "jdbc:postgresql://localhost:55432/flyway_build",
      user: "test",
      password: "test",
      cleanup,
    });
    exec.mockImplementation(mockExec({ stdout: {} }));

    await runChecks({ targetUrl: "jdbc:postgresql://localhost:5432/mydb" }, "enterprise");

    expect(provisionBuildDatabase).toHaveBeenCalledWith("jdbc:postgresql://localhost:5432/mydb");

    const checkCalls = (exec.mock.calls as [string, string[]][]).filter((call) => call[1]?.[0] === "check");

    expect(checkCalls).toHaveLength(4);
    expect(checkCalls[3][1]).toContain("-changes");
    expect(checkCalls[3][1]).toContain(
      "-environments.default_build.url=jdbc:postgresql://localhost:55432/flyway_build",
    );
  });

  it("should call cleanup even when checks fail", async () => {
    provisionBuildDatabase.mockResolvedValue({
      jdbcUrl: "jdbc:postgresql://localhost:55432/flyway_build",
      user: "test",
      password: "test",
      cleanup,
    });
    exec.mockImplementation(
      mockExec({
        stdout: { error: { errorCode: "FAULT", message: "Check failed" } },
        exitCode: 1,
      }),
    );

    await expect(runChecks({ targetUrl: "jdbc:postgresql://localhost:5432/mydb" }, "enterprise")).rejects.toThrow();

    expect(cleanup).toHaveBeenCalled();
  });

  it("should skip provisioning when build inputs are provided", async () => {
    exec.mockImplementation(mockExec({ stdout: {} }));

    await runChecks({ buildUrl: "jdbc:sqlite:build.db", targetUrl: "jdbc:postgresql://localhost/db" }, "enterprise");

    expect(provisionBuildDatabase).not.toHaveBeenCalled();
  });

  it("should skip provisioning for non-enterprise edition", async () => {
    exec.mockImplementation(mockExec({ stdout: {} }));

    await runChecks({ targetUrl: "jdbc:postgresql://localhost/db" }, "teams");

    expect(provisionBuildDatabase).not.toHaveBeenCalled();
  });

  it("should skip provisioning when skipDeploymentChangesReport is true", async () => {
    exec.mockImplementation(mockExec({ stdout: {} }));

    await runChecks({ targetUrl: "jdbc:postgresql://localhost/db", skipDeploymentChangesReport: true }, "enterprise");

    expect(provisionBuildDatabase).not.toHaveBeenCalled();
  });

  it("should skip provisioning when autoProvisionBuildDatabase is false", async () => {
    exec.mockImplementation(mockExec({ stdout: {} }));

    await runChecks({ targetUrl: "jdbc:postgresql://localhost/db", autoProvisionBuildDatabase: false }, "enterprise");

    expect(provisionBuildDatabase).not.toHaveBeenCalled();
  });

  it("should skip provisioning when no targetUrl", async () => {
    exec.mockImplementation(mockExec({ stdout: {} }));

    await runChecks({ targetEnvironment: "production" }, "enterprise");

    expect(provisionBuildDatabase).not.toHaveBeenCalled();
  });

  it("should degrade gracefully when provisioning fails", async () => {
    provisionBuildDatabase.mockRejectedValue(new Error("Docker not available"));
    exec.mockImplementation(mockExec({ stdout: {} }));

    await runChecks({ targetUrl: "jdbc:postgresql://localhost/db" }, "enterprise");

    expect(warning).toHaveBeenCalledWith(expect.stringContaining("Docker not available"));

    const checkCalls = (exec.mock.calls as [string, string[]][]).filter((call) => call[1]?.[0] === "check");

    expect(checkCalls).toHaveLength(3);
  });

  it("should set buildOkToErase to true for provisioned database", async () => {
    provisionBuildDatabase.mockResolvedValue({
      jdbcUrl: "jdbc:postgresql://localhost:55432/flyway_build",
      user: "test",
      password: "test",
      cleanup,
    });
    exec.mockImplementation(mockExec({ stdout: {} }));

    await runChecks({ targetUrl: "jdbc:postgresql://localhost:5432/mydb" }, "enterprise");

    const checkCalls = (exec.mock.calls as [string, string[]][]).filter((call) => call[1]?.[0] === "check");
    const changesCall = checkCalls.find((call) => call[1].includes("-changes"));

    expect(changesCall?.[1]).toContain("-environments.default_build.flyway.cleanDisabled=false");
  });

  it("should mask provisioned password via setSecret", async () => {
    provisionBuildDatabase.mockResolvedValue({
      jdbcUrl: "jdbc:postgresql://localhost:55432/flyway_build",
      user: "test",
      password: "secret_password",
      cleanup,
    });
    exec.mockImplementation(mockExec({ stdout: {} }));

    await runChecks({ targetUrl: "jdbc:postgresql://localhost:5432/mydb" }, "enterprise");

    expect(setSecret).toHaveBeenCalledWith("secret_password");
  });

  it("should warn but not throw when cleanup fails", async () => {
    const failingCleanup = vi.fn().mockRejectedValue(new Error("stop failed"));
    provisionBuildDatabase.mockResolvedValue({
      jdbcUrl: "jdbc:postgresql://localhost:55432/flyway_build",
      user: "test",
      password: "test",
      cleanup: failingCleanup,
    });
    exec.mockImplementation(mockExec({ stdout: {} }));

    await runChecks({ targetUrl: "jdbc:postgresql://localhost:5432/mydb" }, "enterprise");

    expect(warning).toHaveBeenCalledWith(expect.stringContaining("stop failed"));
  });

  it("should skip provisioning when provisionBuildDatabase returns undefined", async () => {
    provisionBuildDatabase.mockResolvedValue(undefined);
    exec.mockImplementation(mockExec({ stdout: {} }));

    await runChecks({ targetUrl: "jdbc:h2:mem:testdb" }, "enterprise");

    const checkCalls = (exec.mock.calls as [string, string[]][]).filter((call) => call[1]?.[0] === "check");

    expect(checkCalls).toHaveLength(3);
  });
});
