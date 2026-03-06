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

  describe("target params", () => {
    it("should use flat params with no environment", () => {
      const inputs: FlywayStateDeploymentInputs = {
        targetUrl: "jdbc:postgresql://localhost/db",
        targetUser: "admin",
        targetPassword: "secret",
        targetSchemas: "public,audit",
      };

      const args = getDeployArgs(inputs);

      expect(args).toContain("-url=jdbc:postgresql://localhost/db");
      expect(args).toContain("-user=admin");
      expect(args).toContain("-password=secret");
      expect(args).toContain("-schemas=public,audit");
    });

    it("should use flat params with default environment", () => {
      const inputs: FlywayStateDeploymentInputs = {
        targetEnvironment: "default",
        targetUrl: "jdbc:postgresql://localhost/db",
        targetUser: "admin",
        targetPassword: "secret",
        targetSchemas: "public,audit",
      };

      const args = getDeployArgs(inputs);

      expect(args).toContain("-environment=default");
      expect(args).toContain("-url=jdbc:postgresql://localhost/db");
      expect(args).toContain("-user=admin");
      expect(args).toContain("-password=secret");
      expect(args).toContain("-schemas=public,audit");
    });

    it("should scope params to named environment", () => {
      const inputs: FlywayStateDeploymentInputs = {
        targetEnvironment: "production",
        targetUrl: "jdbc:postgresql://localhost/db",
        targetUser: "admin",
        targetPassword: "secret",
        targetSchemas: "public,audit",
      };

      const args = getDeployArgs(inputs);

      expect(args).toContain("-environment=production");
      expect(args).toContain("-environments.production.url=jdbc:postgresql://localhost/db");
      expect(args).toContain("-environments.production.user=admin");
      expect(args).toContain("-environments.production.password=secret");
      expect(args).toContain("-environments.production.schemas=public,audit");
    });
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

  it("should include working directory", () => {
    const inputs: FlywayStateDeploymentInputs = {
      workingDirectory: "/app/db",
    };

    const args = getDeployArgs(inputs);

    expect(args).toContain("-workingDirectory=/app/db");
  });

  it("should include extra args", () => {
    const inputs: FlywayStateDeploymentInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      extraArgs: "-X -custom=value",
    };

    const args = getDeployArgs(inputs);

    expect(args).toContain("-X");
    expect(args).toContain("-custom=value");
  });

  it("should not include undefined optional values", () => {
    const inputs: FlywayStateDeploymentInputs = {};

    const args = getDeployArgs(inputs);

    expect(args.filter((a) => a.includes("url")).length).toBe(0);
    expect(args.filter((a) => a.includes("user")).length).toBe(0);
    expect(args.filter((a) => a.includes("password")).length).toBe(0);
    expect(args.filter((a) => a.includes("environment")).length).toBe(0);
  });
});
