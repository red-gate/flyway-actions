import type { FlywayStateDeploymentInputs } from "../src/types.js";
import * as path from "path";

const getInput = vi.fn();
const getBooleanInput = vi.fn();
const setSecret = vi.fn();

vi.doMock("@actions/core", () => ({
  getInput,
  getBooleanInput,
  setSecret,
}));

const { getInputs, maskSecrets } = await import("../src/inputs.js");

describe("getInputs", () => {
  beforeEach(() => {
    getInput.mockReturnValue("");
  });

  it("should return script-path when provided", () => {
    getInput.mockImplementation((name: string) => {
      if (name === "script-path") {
        return "deploy-script.sql";
      }
      return "";
    });

    const inputs = getInputs();

    expect(inputs.scriptPath).toBe("deploy-script.sql");
  });

  it("should return target-url when provided", () => {
    getInput.mockImplementation((name: string) => {
      if (name === "target-url") {
        return "jdbc:postgresql://localhost/db";
      }
      return "";
    });

    const inputs = getInputs();

    expect(inputs.targetUrl).toBe("jdbc:postgresql://localhost/db");
  });

  it("should return undefined for target-url when not provided", () => {
    const inputs = getInputs();

    expect(inputs.targetUrl).toBeUndefined();
  });

  it("should get connection inputs", () => {
    getInput.mockImplementation((name: string) => {
      const values: Record<string, string> = {
        "target-url": "jdbc:postgresql://localhost/db",
        "target-user": "admin",
        "target-password": "secret",
      };
      return values[name] || "";
    });

    const inputs = getInputs();

    expect(inputs.targetUrl).toBe("jdbc:postgresql://localhost/db");
    expect(inputs.targetUser).toBe("admin");
    expect(inputs.targetPassword).toBe("secret");
  });

  it("should get target-environment input", () => {
    getInput.mockImplementation((name: string) => {
      if (name === "target-environment") {
        return "production";
      }
      return "";
    });

    const inputs = getInputs();

    expect(inputs.targetEnvironment).toBe("production");
  });

  it("should get target-schemas input", () => {
    getInput.mockImplementation((name: string) => {
      if (name === "target-schemas") {
        return "public,audit";
      }
      return "";
    });

    const inputs = getInputs();

    expect(inputs.targetSchemas).toBe("public,audit");
  });

  it("should get skip-drift-check input", () => {
    getBooleanInput.mockImplementation((name: string) => name === "skip-drift-check");

    const inputs = getInputs();

    expect(inputs.skipDriftCheck).toBe(true);
  });

  it("should get deployment-report-name input", () => {
    getInput.mockImplementation((name: string) => {
      if (name === "deployment-report-name") {
        return "custom-deployment-report";
      }
      return "";
    });

    const inputs = getInputs();

    expect(inputs.deploymentReportName).toBe("custom-deployment-report");
  });

  it("should get working directory and extra args", () => {
    getInput.mockImplementation((name: string) => {
      const values: Record<string, string> = {
        "working-directory": "/app/db",
        "extra-args": "-X -someFlag=value",
      };
      return values[name] || "";
    });

    const inputs = getInputs();

    expect(inputs.workingDirectory).toBe(path.resolve("/app/db"));
    expect(inputs.extraArgs).toBe("-X -someFlag=value");
  });

  it("should return undefined for optional inputs not provided", () => {
    const inputs = getInputs();

    expect(inputs.scriptPath).toBeUndefined();
    expect(inputs.targetUrl).toBeUndefined();
    expect(inputs.targetUser).toBeUndefined();
    expect(inputs.targetPassword).toBeUndefined();
    expect(inputs.targetEnvironment).toBeUndefined();
    expect(inputs.targetSchemas).toBeUndefined();
    expect(inputs.workingDirectory).toBeUndefined();
    expect(inputs.extraArgs).toBeUndefined();
    expect(inputs.deploymentReportName).toBeUndefined();
  });
});

describe("maskSecrets", () => {
  it("should mask password", () => {
    const inputs: FlywayStateDeploymentInputs = {
      targetPassword: "secret123",
    };

    maskSecrets(inputs);

    expect(setSecret).toHaveBeenCalledWith("secret123");
  });

  it("should not call setSecret when no password present", () => {
    const inputs: FlywayStateDeploymentInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      targetUser: "admin",
    };

    maskSecrets(inputs);

    expect(setSecret).not.toHaveBeenCalled();
  });
});
