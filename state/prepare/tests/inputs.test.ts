import type { FlywayStatePrepareInputs } from "../src/types.js";
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

  it("should get generate-undo input", () => {
    getBooleanInput.mockImplementation((name: string) => name === "generate-undo");

    const inputs = getInputs();

    expect(inputs.generateUndo).toBe(true);
  });

  it("should get fail-on-drift input", () => {
    getBooleanInput.mockImplementation((name: string) => name === "fail-on-drift");

    const inputs = getInputs();

    expect(inputs.failOnDrift).toBe(true);
  });

  it("should get skip-drift-check input", () => {
    getBooleanInput.mockImplementation((name: string) => name === "skip-drift-check");

    const inputs = getInputs();

    expect(inputs.skipDriftCheck).toBe(true);
  });

  it("should get fail-on-code-review input", () => {
    getBooleanInput.mockImplementation((name: string) => name === "fail-on-code-review");

    const inputs = getInputs();

    expect(inputs.failOnCodeReview).toBe(true);
  });

  it("should get skip-code-review input", () => {
    getBooleanInput.mockImplementation((name: string) => name === "skip-code-review");

    const inputs = getInputs();

    expect(inputs.skipCodeReview).toBe(true);
  });

  it("should get drift-report-name input", () => {
    getInput.mockImplementation((name: string) => {
      if (name === "drift-report-name") {
        return "custom-report";
      }
      return "";
    });

    const inputs = getInputs();

    expect(inputs.driftReportName).toBe("custom-report");
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

    expect(inputs.targetUrl).toBeUndefined();
    expect(inputs.targetUser).toBeUndefined();
    expect(inputs.targetPassword).toBeUndefined();
    expect(inputs.targetEnvironment).toBeUndefined();
    expect(inputs.targetSchemas).toBeUndefined();
    expect(inputs.workingDirectory).toBeUndefined();
    expect(inputs.extraArgs).toBeUndefined();
    expect(inputs.driftReportName).toBeUndefined();
  });
});

describe("maskSecrets", () => {
  it("should mask password", () => {
    const inputs: FlywayStatePrepareInputs = {
      targetPassword: "secret123",
    };

    maskSecrets(inputs);

    expect(setSecret).toHaveBeenCalledWith("secret123");
  });

  it("should not call setSecret when no password present", () => {
    const inputs: FlywayStatePrepareInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      targetUser: "admin",
    };

    maskSecrets(inputs);

    expect(setSecret).not.toHaveBeenCalled();
  });
});
