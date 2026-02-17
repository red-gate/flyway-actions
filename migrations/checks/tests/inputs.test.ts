import type { FlywayMigrationsChecksInputs } from "../src/types.js";
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
    getBooleanInput.mockReturnValue(false);
  });

  it("should return target connection inputs when provided", () => {
    getInput.mockImplementation((name: string) => {
      const values: Record<string, string> = {
        "target-url": "jdbc:postgresql://localhost/db",
        "target-user": "admin",
        "target-password": "secret",
        "target-environment": "production",
        "target-schemas": "public,audit",
      };
      return values[name] || "";
    });

    const inputs = getInputs();

    expect(inputs.targetUrl).toBe("jdbc:postgresql://localhost/db");
    expect(inputs.targetUser).toBe("admin");
    expect(inputs.targetPassword).toBe("secret");
    expect(inputs.targetEnvironment).toBe("production");
    expect(inputs.targetSchemas).toBe("public,audit");
  });

  it("should return build connection inputs when provided", () => {
    getInput.mockImplementation((name: string) => {
      const values: Record<string, string> = {
        "build-environment": "shadow",
        "build-url": "jdbc:postgresql://localhost/build",
        "build-user": "builduser",
        "build-password": "buildsecret",
        "build-schemas": "public",
      };
      return values[name] || "";
    });

    const inputs = getInputs();

    expect(inputs.buildEnvironment).toBe("shadow");
    expect(inputs.buildUrl).toBe("jdbc:postgresql://localhost/build");
    expect(inputs.buildUser).toBe("builduser");
    expect(inputs.buildPassword).toBe("buildsecret");
    expect(inputs.buildSchemas).toBe("public");
  });

  it("should return boolean flags from getBooleanInput", () => {
    getBooleanInput.mockImplementation((name: string) => {
      const values: Record<string, boolean> = {
        "generate-report": true,
        "fail-on-drift": false,
        "fail-on-code-review": true,
      };
      return values[name] ?? false;
    });

    const inputs = getInputs();

    expect(inputs.generateReport).toBe(true);
    expect(inputs.failOnDrift).toBe(false);
    expect(inputs.failOnCodeReview).toBe(true);
  });

  it("should return migration version and cherry pick inputs", () => {
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

  it("should resolve working directory to absolute path", () => {
    getInput.mockImplementation((name: string) => {
      if (name === "working-directory") {
        return "/app/db";
      }
      return "";
    });

    const inputs = getInputs();

    expect(inputs.workingDirectory).toBe(path.resolve("/app/db"));
  });

  it("should return extra args", () => {
    getInput.mockImplementation((name: string) => {
      if (name === "extra-args") {
        return "-X -someFlag=value";
      }
      return "";
    });

    const inputs = getInputs();

    expect(inputs.extraArgs).toBe("-X -someFlag=value");
  });

  it("should return undefined for optional inputs not provided", () => {
    const inputs = getInputs();

    expect(inputs.targetUrl).toBeUndefined();
    expect(inputs.targetUser).toBeUndefined();
    expect(inputs.targetPassword).toBeUndefined();
    expect(inputs.targetEnvironment).toBeUndefined();
    expect(inputs.targetSchemas).toBeUndefined();
    expect(inputs.buildEnvironment).toBeUndefined();
    expect(inputs.buildUrl).toBeUndefined();
    expect(inputs.buildUser).toBeUndefined();
    expect(inputs.buildPassword).toBeUndefined();
    expect(inputs.buildSchemas).toBeUndefined();
    expect(inputs.targetMigrationVersion).toBeUndefined();
    expect(inputs.cherryPick).toBeUndefined();
    expect(inputs.workingDirectory).toBeUndefined();
    expect(inputs.extraArgs).toBeUndefined();
  });
});

describe("maskSecrets", () => {
  it("should mask target password", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      targetPassword: "secret123",
      generateReport: true,
      failOnDrift: true,
      failOnCodeReview: true,
    };

    maskSecrets(inputs);

    expect(setSecret).toHaveBeenCalledWith("secret123");
  });

  it("should mask build password", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      buildPassword: "buildsecret",
      generateReport: true,
      failOnDrift: true,
      failOnCodeReview: true,
    };

    maskSecrets(inputs);

    expect(setSecret).toHaveBeenCalledWith("buildsecret");
  });

  it("should mask both passwords when both present", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      targetPassword: "secret123",
      buildPassword: "buildsecret",
      generateReport: true,
      failOnDrift: true,
      failOnCodeReview: true,
    };

    maskSecrets(inputs);

    expect(setSecret).toHaveBeenCalledWith("secret123");
    expect(setSecret).toHaveBeenCalledWith("buildsecret");
  });

  it("should not call setSecret when no passwords present", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
      generateReport: true,
      failOnDrift: true,
      failOnCodeReview: true,
    };

    maskSecrets(inputs);

    expect(setSecret).not.toHaveBeenCalled();
  });
});
