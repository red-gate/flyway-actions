import * as path from "path";
import type { FlywayMigrationsDeploymentInputs } from "../src/types.js";

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
      if (name === "target-url") return "jdbc:postgresql://localhost/db";
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
      if (name === "target-environment") return "production";
      return "";
    });

    const inputs = getInputs();
    expect(inputs.targetEnvironment).toBe("production");
  });

  it("should get target-schemas input", () => {
    getInput.mockImplementation((name: string) => {
      if (name === "target-schemas") return "public,audit";
      return "";
    });

    const inputs = getInputs();
    expect(inputs.targetSchemas).toBe("public,audit");
  });

  it("should get target-migration-version and cherry-pick inputs", () => {
    getInput.mockImplementation((name: string) => {
      const values: Record<string, string> = {
        "target-migration-version": "5.0",
        "cherry-pick": "3.0,4.0",
      };
      return values[name] || "";
    });

    const inputs = getInputs();
    expect(inputs.targetMigrationVersion).toBe("5.0");
    expect(inputs.cherryPick).toBe("3.0,4.0");
  });

  it("should get skip-drift-check input", () => {
    getBooleanInput.mockReturnValue(true);

    const inputs = getInputs();
    expect(inputs.skipDriftCheck).toBe(true);
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
    expect(inputs.targetMigrationVersion).toBeUndefined();
    expect(inputs.cherryPick).toBeUndefined();
    expect(inputs.workingDirectory).toBeUndefined();
    expect(inputs.extraArgs).toBeUndefined();
  });
});

describe("maskSecrets", () => {
  it("should mask password", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      targetPassword: "secret123",
    };

    maskSecrets(inputs);

    expect(setSecret).toHaveBeenCalledWith("secret123");
  });

  it("should not call setSecret when no password present", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      targetUser: "admin",
    };

    maskSecrets(inputs);

    expect(setSecret).not.toHaveBeenCalled();
  });
});
