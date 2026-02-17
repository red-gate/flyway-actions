import type { FlywayMigrationsChecksInputs } from "../src/types.js";
import * as path from "path";

const getInput = vi.fn();
const setSecret = vi.fn();

vi.doMock("@actions/core", () => ({
  getInput,
  setSecret,
}));

const { getInputs, maskSecrets } = await import("../src/inputs.js");

describe("getInputs", () => {
  beforeEach(() => {
    getInput.mockReturnValue("");
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
    };

    maskSecrets(inputs);

    expect(setSecret).toHaveBeenCalledWith("secret123");
  });

  it("should not call setSecret when no passwords present", () => {
    const inputs: FlywayMigrationsChecksInputs = {
      targetUrl: "jdbc:postgresql://localhost/db",
    };

    maskSecrets(inputs);

    expect(setSecret).not.toHaveBeenCalled();
  });
});
