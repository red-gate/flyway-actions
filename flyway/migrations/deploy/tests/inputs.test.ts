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

  it("should return url when provided", () => {
    getInput.mockImplementation((name: string) => {
      if (name === "url") return "jdbc:postgresql://localhost/db";
      return "";
    });

    const inputs = getInputs();
    expect(inputs.url).toBe("jdbc:postgresql://localhost/db");
  });

  it("should return undefined for url when not provided", () => {
    const inputs = getInputs();
    expect(inputs.url).toBeUndefined();
  });

  it("should get connection inputs", () => {
    getInput.mockImplementation((name: string) => {
      const values: Record<string, string> = {
        url: "jdbc:postgresql://localhost/db",
        user: "admin",
        password: "secret",
      };
      return values[name] || "";
    });

    const inputs = getInputs();
    expect(inputs.url).toBe("jdbc:postgresql://localhost/db");
    expect(inputs.user).toBe("admin");
    expect(inputs.password).toBe("secret");
  });

  it("should get environment input", () => {
    getInput.mockImplementation((name: string) => {
      if (name === "environment") return "production";
      return "";
    });

    const inputs = getInputs();
    expect(inputs.environment).toBe("production");
  });

  it("should get target and cherry-pick inputs", () => {
    getInput.mockImplementation((name: string) => {
      const values: Record<string, string> = {
        target: "5.0",
        "cherry-pick": "3.0,4.0",
      };
      return values[name] || "";
    });

    const inputs = getInputs();
    expect(inputs.target).toBe("5.0");
    expect(inputs.cherryPick).toBe("3.0,4.0");
  });

  it("should get skip-drift input", () => {
    getBooleanInput.mockReturnValue(true);

    const inputs = getInputs();
    expect(inputs.skipDrift).toBe(true);
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
    expect(inputs.url).toBeUndefined();
    expect(inputs.user).toBeUndefined();
    expect(inputs.password).toBeUndefined();
    expect(inputs.environment).toBeUndefined();
    expect(inputs.target).toBeUndefined();
    expect(inputs.cherryPick).toBeUndefined();
    expect(inputs.workingDirectory).toBeUndefined();
    expect(inputs.extraArgs).toBeUndefined();
  });
});

describe("maskSecrets", () => {
  it("should mask password", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      password: "secret123",
    };

    maskSecrets(inputs);

    expect(setSecret).toHaveBeenCalledWith("secret123");
  });

  it("should not call setSecret when no password present", () => {
    const inputs: FlywayMigrationsDeploymentInputs = {
      url: "jdbc:postgresql://localhost/db",
      user: "admin",
    };

    maskSecrets(inputs);

    expect(setSecret).not.toHaveBeenCalled();
  });
});
