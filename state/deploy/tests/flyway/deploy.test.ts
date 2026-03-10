import type { FlywayStateDeploymentInputs } from "../../src/types.js";
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

const { deploy, getDeployArgs } = await import("../../src/flyway/deploy.js");

describe("deploy", () => {
  it("should set exit-code output on success", async () => {
    exec.mockImplementation(mockExec({ stdout: {} }));

    await deploy({ targetUrl: "jdbc:sqlite:test.db" });

    expect(setOutput).toHaveBeenCalledWith("exit-code", "0");
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

    await deploy({ targetUrl: "jdbc:h2:mem:test" });

    expect(info).toHaveBeenCalledWith(
      "No snapshot was generated or stored in the target database as snapshots are not supported for this database type.",
    );
  });

  it("should throw when deploy fails with an unrecognised error", async () => {
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

    await expect(deploy({ targetUrl: "jdbc:h2:mem:test" })).rejects.toThrow("Flyway deploy failed with exit code 1");
  });
});

describe("getDeployArgs", () => {
  it("should build args with deploy command", () => {
    const inputs: FlywayStateDeploymentInputs = {};

    const args = getDeployArgs(inputs);

    expect(args[0]).toBe("deploy");
  });

  it("should include script-path when provided", () => {
    const inputs: FlywayStateDeploymentInputs = {
      scriptPath: "deploy-script.sql",
    };

    const args = getDeployArgs(inputs);

    expect(args).toContain("-deploy.scriptFilename=deploy-script.sql");
  });

  it("should not include script-path when not provided", () => {
    const inputs: FlywayStateDeploymentInputs = {};

    const args = getDeployArgs(inputs);

    expect(args.some((a) => a.includes("scriptFilename"))).toBe(false);
  });

  it("should include -deploy.saveSnapshot=true when saveSnapshot is true", () => {
    const inputs: FlywayStateDeploymentInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      saveSnapshot: true,
    };

    const args = getDeployArgs(inputs);

    expect(args).toContain("-deploy.saveSnapshot=true");
  });

  it("should omit saveSnapshot when not set", () => {
    const inputs: FlywayStateDeploymentInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
    };

    const args = getDeployArgs(inputs);

    expect(args.some((a) => a.includes("saveSnapshot"))).toBe(false);
  });
});
