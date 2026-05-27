import type { CommitInputs, FlywayMigrationsGenerateInputs } from "../src/types.js";
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

  it("should return source when provided", () => {
    getInput.mockImplementation((name: string) => (name === "source" ? "schemaModel" : ""));

    const inputs = getInputs();

    expect(inputs.source).toBe("schemaModel");
  });

  it("should return migration-types when provided", () => {
    getInput.mockImplementation((name: string) => (name === "migration-types" ? "versioned,undo" : ""));

    const inputs = getInputs();

    expect(inputs.migrationTypes).toBe("versioned,undo");
  });

  it("should return migration-description when provided", () => {
    getInput.mockImplementation((name: string) => (name === "migration-description" ? "add_orders_table" : ""));

    const inputs = getInputs();

    expect(inputs.migrationDescription).toBe("add_orders_table");
  });

  it("should get build connection inputs", () => {
    getInput.mockImplementation((name: string) => {
      const values: Record<string, string> = {
        "build-environment": "build",
        "build-url": "jdbc:postgresql://localhost/build",
        "build-user": "admin",
        "build-password": "shh",
        "build-schemas": "public,audit",
      };
      return values[name] || "";
    });

    const inputs = getInputs();

    expect(inputs.buildEnvironment).toBe("build");
    expect(inputs.buildUrl).toBe("jdbc:postgresql://localhost/build");
    expect(inputs.buildUser).toBe("admin");
    expect(inputs.buildPassword).toBe("shh");
    expect(inputs.buildSchemas).toBe("public,audit");
  });

  it("should resolve working directory", () => {
    getInput.mockImplementation((name: string) => (name === "working-directory" ? "/app/db" : ""));

    const inputs = getInputs();

    expect(inputs.workingDirectory).toBe(path.resolve("/app/db"));
  });

  it("should pass through extra args", () => {
    getInput.mockImplementation((name: string) => (name === "extra-args" ? "-X -someFlag=value" : ""));

    const inputs = getInputs();

    expect(inputs.extraArgs).toBe("-X -someFlag=value");
  });

  it("should return undefined for optional inputs not provided", () => {
    const inputs = getInputs();

    expect(inputs.source).toBeUndefined();
    expect(inputs.migrationTypes).toBeUndefined();
    expect(inputs.migrationDescription).toBeUndefined();
    expect(inputs.buildEnvironment).toBeUndefined();
    expect(inputs.buildUrl).toBeUndefined();
    expect(inputs.buildUser).toBeUndefined();
    expect(inputs.buildPassword).toBeUndefined();
    expect(inputs.buildSchemas).toBeUndefined();
    expect(inputs.workingDirectory).toBeUndefined();
    expect(inputs.extraArgs).toBeUndefined();
    expect(inputs.commit.branch).toBeUndefined();
  });

  it("should read commit-migrations boolean", () => {
    getBooleanInput.mockImplementation((name: string) => name === "commit-migrations");

    const inputs = getInputs();

    expect(inputs.commit.migrations).toBe(true);
  });

  it("should pass commit metadata through verbatim from inputs", () => {
    getInput.mockImplementation((name: string) => {
      const values: Record<string, string> = {
        "commit-message": "chore: my message",
        "commit-user-name": "Alice",
        "commit-user-email": "alice@example.com",
        "commit-branch": "feature/migrations",
      };
      return values[name] || "";
    });

    const inputs = getInputs();

    expect(inputs.commit.message).toBe("chore: my message");
    expect(inputs.commit.userName).toBe("Alice");
    expect(inputs.commit.userEmail).toBe("alice@example.com");
    expect(inputs.commit.branch).toBe("feature/migrations");
  });
});

const defaultCommit: CommitInputs = {
  migrations: false,
  message: "",
  userName: "",
  userEmail: "",
};

describe("maskSecrets", () => {
  it("should mask build password", () => {
    const inputs: FlywayMigrationsGenerateInputs = {
      commit: defaultCommit,
      buildPassword: "shh",
    };

    maskSecrets(inputs);

    expect(setSecret).toHaveBeenCalledWith("shh");
  });

  it("should not call setSecret when no password present", () => {
    const inputs: FlywayMigrationsGenerateInputs = {
      commit: defaultCommit,
      buildUrl: "jdbc:postgresql://localhost/build",
      buildUser: "admin",
    };

    maskSecrets(inputs);

    expect(setSecret).not.toHaveBeenCalled();
  });
});
